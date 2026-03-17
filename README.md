# 🛡️ Argos — Network Intelligence & Packet Factory

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-magenta)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![Architecture](https://img.shields.io/badge/Architecture-Modular-blueviolet)

```text
  █████╗ ██████╗  ██████╗  ██████╗ ███████╗
  ██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗██╔════╝
  ███████║██████╔╝██║  ███╗██║   ██║███████╗
  ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
  ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
```

**Argos** es una herramienta CLI empresarial con interfaz de consola avanzada (**Elite Purple Edition**) para ingeniería de red. Permite el descubrimiento de dispositivos, pruebas de rendimiento LAN y forjado de paquetes a medida (Capas 2-4 OSI). Orientada estrictamente para entornos locales (**RFC 1918**) sin dependencias de salida a Internet.

---

## 📂 Estructura / Structure

* **`argos.py`**: El núcleo que arranca la herramienta. (Main entry point).
* **`modules/`**:
    * **`cli_ui.py`**: Interfaz visual en Morado/Magenta con la librería Rich. (UI logic).
    * **`discovery.py`**: Escaneo de red y detección de dispositivos. (Network discovery).
    * **`packet_factory.py`**: Creación de paquetes a medida. (Packet crafting).
    * **`speed_test.py`**: Cliente/Servidor TCP para medir el throughput. (LAN Speed test).
    * **`updater.py`**: Gestor de actualizaciones y parches desde GitHub. (Update manager).
    * **`net_utils.py`**: Herramientas para validar IPs y tarjetas de red. (Network helpers).
* **`requirements.txt`**: Librerías externas necesarias (Scapy, Rich, Psutil). (Dependencies).

---

## 🚀 Características (Features)

1.  **Discovery**: Escaneo local usando **Scapy (ARP)** con detección de MAC, Hostname y fabricante (Vendor).
2.  **Speed Test**: Interfaz dual (Servidor/Cliente) para medir velocidad bruta (**Mbps**), latencia y Jitter en la red local.
3.  **Packet Factory**: Manipulación de bajo nivel:
    * **Capa 2**: Tramas Ethernet y peticiones ARP.
    * **Capa 3**: Control de IP y TTL incremental (Traceroute).
    * **Capa 4**: Forjado manual de **Flags TCP** (SYN, ACK, RST, FIN) para auditoría de Firewalls.
4.  **Auto-Update**: Verificación de versiones contra el repositorio oficial y aplicación de parches en caliente.

---

## 🛠️ Requisitos y Configuración

Se recomienda una consola con soporte **Truecolor** (Windows Terminal, iTerm2 o similares).

* **Python 3.10+**
* **Permisos de Administrador / Root**: Obligatorio para la manipulación de paquetes de bajo nivel.

```bash
# Instalar dependencias
pip install -r requirements.txt

# Ejecutar Argos
python argos.py
```

---

## 🧠 Metodología (AI-Assisted)

Este proyecto ha sido diseñado bajo una arquitectura de **Desarrollo Asistido por IA**, utilizando modelos de lenguaje avanzados para la optimización de lógica de red y diseño de UX en consola. Mi rol como desarrollador ha sido la arquitectura del sistema, supervisión técnica y validación de seguridad.

---

## ⚠️ Aviso Legal / License

Este software es para fines educativos y auditorías autorizadas. El uso en redes ajenas sin permiso es responsabilidad del usuario.

**Licencia: MIT** - Siéntete libre de usar, modificar y mejorar este proyecto para tu propio porfolio.
# JNC-NetTools // Versión ADA - Documentación Técnica

## 1. Introducción

JNC-NetTools es una suite integral de diagnóstico y gestión de redes diseñada para sistemas Linux. Proporciona una interfaz gráfica de usuario (GUI) para tareas de red avanzadas que normalmente requieren interacciones complejas en la línea de comandos.

### Capacidades Clave
- Gestión de Interfaces de Red (IP, Subred, Puerta de Enlace)
- Bridging Avanzado (Trunks VLAN, Passthrough, Wi-Fi a Ethernet)
- Escaneo de Redes y Puertos (Integración con Nmap)
- Análisis de Tráfico y Sniffing de Paquetes (Integración con Scapy)
- Diagnóstico de Red (Ping, Traceroute, DNS)
- Generación Automatizada de Informes (HTML)

## 2. Requisitos del Sistema

### Sistema Operativo
- Linux (Probado en Linux Mint / Ubuntu / Debian)
- Privilegios de Root: Requeridos para la mayoría de las operaciones (manipulación de interfaces, escaneo de sockets raw, sniffing)

### Dependencias de Software

#### Herramientas del Sistema
| Herramienta   | Descripción                              | Obligatoria |
|---------------|------------------------------------------|-------------|
| iproute2      | Comando `ip`                             | Sí          |
| nmap          | Mapeador de redes                        | Sí          |
| tcpdump       | Captura de paquetes                      | Sí          |
| dnsmasq       | Servidor DHCP                            | Sí          |
| hostapd       | Punto de acceso Wi-Fi                    | Sí          |
| iw            | Configuración inalámbrica                | Sí          |
| ethtool       | Estadísticas de interfaz                 | Opcional    |

#### Bibliotecas de Python
| Biblioteca     | Uso Principal                          |
|----------------|----------------------------------------|
| PyQt6          | Framework GUI                          |
| python-nmap    | Wrapper de Nmap                        |
| scapy          | Manipulación y sniffing de paquetes    |
| psutil         | Monitoreo del sistema                  |
| pyroute2       | Redes avanzadas en Linux (Netlink)     |

- Python: 3.8 o superior

## 3. Instalación y Ejecución

### Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/inlutec/JNC-NetTools.git
cd JNC-NetTools

# 2. Instalar dependencias del sistema
sudo apt update
sudo apt install python3-pip nmap tcpdump dnsmasq hostapd iw

# 3. Configurar entorno virtual
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Si no existe requirements.txt, instalar manualmente:
# pip install PyQt6 python-nmap scapy psutil pyroute2
```

### Ejecución

```bash
bash JNC-Scan_Launcher.sh
```

> Nota: El launcher gestiona automáticamente la activación del entorno virtual y los privilegios de root (se solicitará la contraseña sudo).

## 4. Arquitectura Técnica

La aplicación sigue una arquitectura modular que separa claramente la lógica del núcleo (backend) de la interfaz gráfica (frontend).

### Estructura de Directorios

```
JNC-NetTools/
├── main.py                     # Punto de entrada principal
├── JNC-Scan_Launcher.sh        # Script de lanzamiento con sudo
├── requirements.txt            # Dependencias Python (si existe)
├── src/
│   ├── core/                   # Lógica Backend
│   │   ├── network_manager.py  # Gestión de interfaces, bridges, DHCP, Wi-Fi AP
│   │   ├── scanner.py          # Escáner de red y puertos (Nmap)
│   │   ├── sniffer.py          # Sniffer con Scapy
│   │   ├── vlan_scanner.py     # Detección pasiva de VLANs (tcpdump)
│   │   └── diagnostics.py      # Ping, traceroute, DNS lookup
│   ├── gui/                    # Frontend PyQt6
│   │   ├── main_window.py      # Ventana principal y pestañas
│   │   ├── styles.py           # Hojas de estilo QSS
│   │   └── widgets/            # Widgets por funcionalidad
│   │       ├── ip_config.py
│   │       ├── vlan_bridge.py
│   │       ├── scanner_view.py
│   │       ├── port_scanner.py
│   │       ├── sniffer_view.py
│   │       └── diagnostics_view.py
│   └── utils/
│       └── report_generator.py # Generación de informes HTML
```

## 5. Funcionalidades Detalladas e Implementación Técnica

### A. Configuración IP
- Uso de `psutil` + `pyroute2` para lectura
- Aplicación persistente mediante `nmcli` (NetworkManager)
- Refresco en tiempo real de interfaces

### B. VLAN y Bridging Avanzado
- Creación de VLANs: `ip link add link <dev> name <dev.id> type vlan id <id>`
- Bridges: `ip link add name <br> type bridge`
- Servidor DHCP integrado con `dnsmasq`
- AP Wi-Fi con `hostapd` + configuración dinámica
- Soporte automático para modo 4addr (WDS) en interfaces Wi-Fi cliente
- Escáner pasivo de VLANs mediante `tcpdump -e` + regex 802.1Q

### C. Escáner de Red (Host Discovery)
- Motor: Nmap
- Prioriza escaneo ARP en redes locales
- Soporte completo para detener escaneo en ejecución
- Filtros en tiempo real (Up/Down)

### D. Escáner de Puertos
- Modos: TCP Connect (`-sT`), UDP (`-sU`), o ambos
- Optimizado con `--min-rate 1000 -T4`
- Oculta automáticamente puertos cerrados en rangos grandes (>500)
- Ejecutado en `QThread` para mantener GUI receptiva

### E. Sniffer de Paquetes
- Motor: `scapy.sniff`
- Soporte completo para filtros BPF
- Decodificación de capas Ethernet/IP/TCP/UDP/ICMP
- Detección automática de anomalías (RST, ICMP Unreachable, retransmisiones)
- Vista separada de "Todo el tráfico" vs "Solo anomalías"

### F. Diagnósticos
- Wrappers con análisis de salida para: `ping`, `traceroute`, `nslookup`

### G. Generación de Informes
- Informe HTML completo con todos los resultados de la sesión
- Estilizado y con timestamps

## 6. Guía para Desarrolladores

### Añadir una nueva pestaña
1. Crear widget en `src/gui/widgets/nueva_herramienta.py`
2. Heredar de `QWidget`
3. Importar en `src/gui/main_window.py`
4. Añadir: `self.tabs.addTab(NuevaHerramienta(), "Nueva Herramienta")`

### Modificar escaneos Nmap
- Editar `src/core/scanner.py` → método `scan()`
- Añadir flags como `-O` (detección SO) o `-sV` (versiones)

### Personalizar el sniffer
- Editar `src/core/sniffer.py` → función `process_packet`
- Añadir detección de payloads específicos (HTTP, malware, etc.)

### Cambiar estilos
- Editar `src/gui/styles.py` (QSS)

## 7. Solución de Problemas Comunes

| Problema                              | Causa más común                              | Solución                                                                 |
|---------------------------------------|----------------------------------------------|--------------------------------------------------------------------------|
| "Operation not supported" (Error 95)  | Wi-Fi no soporta modo 4addr/WDS              | Usar tarjeta compatible o modo "Wi-Fi AP" en lugar de puente cliente     |
| `iw: command not found`               | Herramienta `iw` no instalada                | `sudo apt install iw`                                                    |
| Sin resultados en escaneos            | No ejecutado como root o firewall bloqueando | Usar el launcher oficial / desactivar temporalmente ufw                  |
| UI se congela en sniffer              | Volumen de tráfico muy alto                  | Aplicar filtro BPF estricto (ej. `tcp port 80`)                          |

¡Listo para copiar y pegar directamente en tu `README.md` de GitHub!  
Mantendrá perfectamente el formato con tablas, código y estructura de carpetas.

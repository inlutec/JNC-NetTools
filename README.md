JNC-NetTools // Versión ADA - Documentación Técnica
1. Introducción
JNC-NetTools es una suite integral de diagnóstico y gestión de redes diseñada para sistemas Linux . Proporciona una interfaz gráfica de usuario (GUI) para tareas de red avanzadas que normalmente requieren interacciones complejas en la línea de comandos.
Capacidades Clave:
    • Gestión de Interfaces de Red (IP, Subred, Puerta de Enlace).
    • Bridging Avanzado (Trunks VLAN, Passthrough, Wi-Fi a Ethernet).
    • Escaneo de Redes y Puertos (Integración con Nmap).
    • Análisis de Tráfico y Sniffing de Paquetes (Integración con Scapy).
    • Diagnóstico de Red (Ping, Traceroute, DNS).
    • Generación Automatizada de Informes (HTML).

2. Requisitos del Sistema
Sistema Operativo
    • Linux (Probado en Linux Mint / Ubuntu / Debian).
    • Privilegios de Root: Requeridos para la mayoría de las operaciones (manipulación de interfaces, escaneo de sockets raw, sniffing).
Dependencias de Software
La aplicación depende de herramientas de red estándar de Linux y bibliotecas de Python:
    • Python: 3.8 o superior.
    • Herramientas del Sistema:
        ◦ iproute2 (comando ip)
        ◦ nmap (Mapeador de Redes)
        ◦ tcpdump (Captura de paquetes)
        ◦ dnsmasq (Servidor DHCP)
        ◦ hostapd (Punto de Acceso Wi-Fi)
        ◦ iw (Configuración inalámbrica)
        ◦ ethtool (Estadísticas de interfaz - opcional)
Bibliotecas de Python
    • PyQt6: Framework GUI.
    • python-nmap: Wrapper de Python para Nmap.
    • scapy: Manipulación y sniffing de paquetes.
    • psutil: Monitoreo del sistema.
    • pyroute2: Redes avanzadas en Linux (Netlink).

3. Instalación y Ejecución
Instalación
    1. Clonar el repositorio:
       git clone <url_del_repositorio>
       cd JNC-Scan
    2. Instalar Dependencias del Sistema:
       sudo apt update
       sudo apt install python3-pip nmap tcpdump dnsmasq hostapd iw
    3. Configurar el Entorno Python:
       python3 -m venv venv
       source venv/bin/activate
       pip install -r requirements.txt
       (Si falta 
       requirements.txt, instale manualmente: pip install PyQt6 python-nmap scapy psutil pyroute2)
Ejecución
Para ejecutar la aplicación, utilice el script de lanzamiento proporcionado que gestiona los permisos de root y la activación del entorno virtual:
bash JNC-Scan_Launcher.sh
Nota: Se le solicitará su contraseña de sudo.






4. Arquitectura Técnica
La aplicación sigue una arquitectura modular que separa la Lógica del Núcleo (Backend) de la GUI (Frontend).
Estructura de Directorios
JNC-Scan/
├── main.py                 # Punto de entrada
├── JNC-Scan_Launcher.sh    # Script de inicio
├── src/
│   ├── core/               # Lógica Backend
│   │   ├── network_manager.py  # Lógica de Interfaz, Bridge, DHCP, Wi-Fi
│   │   ├── scanner.py          # Lógica de Escáner de Puertos/Red Nmap
│   │   ├── sniffer.py          # Lógica de Sniffer Scapy
│   │   ├── vlan_scanner.py     # Detección pasiva de VLAN (tcpdump)
│   │   └── diagnostics.py      # Ping, Traceroute, etc.
│   ├── gui/                # Frontend (PyQt6)
│   │   ├── main_window.py      # Ventana principal de la aplicación
│   │   ├── styles.py           # Hojas de estilo CSS/QSS
│   │   └── widgets/            # Pestañas de funciones individuales
│   │       ├── ip_config.py
│   │       ├── vlan_bridge.py
│   │       ├── scanner_view.py
│   │       ├── port_scanner.py
│   │       ├── sniffer_view.py
│   │       └── diagnostics_view.py
│   └── utils/
│       └── report_generator.py # Generación de Informes HTML




5. Funcionalidades Detalladas e Implementación Técnica
A. Configuración IP
    • Función: Ver y configurar direcciones IP, subredes y puertas de enlace.
    • Implementación:
        ◦ Utiliza psutil y pyroute2 para obtener el estado de la interfaz.
        ◦ Utiliza nmcli (CLI de NetworkManager) para aplicar configuraciones persistentes (IP Estática o DHCP).
        ◦ Refresco: Actualizaciones en tiempo real de la lista de interfaces.
B. VLAN y Bridging
    • Función: Crear puentes de red complejos.
        ◦ VLAN Trunk: Puentea un ID de VLAN específico desde un puerto trunk a un puerto de acceso.
        ◦ Passthrough: Puentea transparentemente dos interfaces.
        ◦ Bridging Wi-Fi AP: Crea un punto de acceso Wi-Fi puenteado a una red cableada.
    • Detalles Técnicos:
        ◦ VLANs: Creadas usando ip link add link <dev> name <dev.id> type vlan id <id>.
        ◦ Bridges: Creados usando ip link add name <br> type bridge.
        ◦ Servidor DHCP: Lanza un proceso dnsmasq vinculado a la interfaz del puente para servir direcciones IP a los clientes conectados.
        ◦ Wi-Fi AP: Genera un hostapd.conf temporal y lanza hostapd.
        ◦ Bridging de Cliente Wi-Fi (Corrección Error 95): Intenta automáticamente habilitar el modo 4addr (WDS) usando iw dev <iface> set 4addr on para permitir que los clientes Wi-Fi sean puenteados. Maneja los errores EOPNOTSUPP con elegancia.
        ◦ Escáner Pasivo de VLAN: Utiliza tcpdump -e para capturar cabeceras y análisis regex para detectar etiquetas 802.1Q en un puerto trunk sin unirse a la VLAN.



C. Escáner de Red (Descubrimiento)
    • Función: Descubre dispositivos activos en un rango de red (CIDR).
    • Implementación:
        ◦ Motor: nmap.
        ◦ Método: Escaneo ARP/Ping (lógica equivalente a -sn, pero usamos -sT con skip_discovery=False para asegurar verificación activa).
        ◦ Optimización: Prioriza ARP para redes locales para mayor velocidad.
        ◦ Características: Registro en tiempo real, capacidad de "Detener Escaneo", Filtros de Estado (Up/Down).
D. Escáner de Puertos
    • Función: Análisis detallado de una IP objetivo específica.
    • Implementación:
        ◦ Motor: nmap.
        ◦ Modos: TCP Connect (-sT), UDP (-sU), o Ambos.
        ◦ Rendimiento: Utiliza --min-rate 1000 y -T4 para velocidad.
        ◦ Rangos Grandes: Oculta automáticamente los puertos "Cerrados" si se escanean >500 puertos para evitar congelamientos de la UI.
        ◦ Hilos: Se ejecuta en un QThread para mantener la GUI receptiva.
E. Sniffer de Paquetes
    • Función: Análisis de tráfico en tiempo real.
    • Implementación:
        ◦ Motor: scapy.sniff.
        ◦ Filtros: Soporta BPF (ej. tcp port 80) y Filtro IP Personalizado (post-filtro basado en GUI).
        ◦ Análisis:
            ▪ Decodifica capas Ethernet, IP, TCP, UDP, ICMP.
            ▪ Detección de Anomalías: Resalta banderas "RST" (Reinicio de Conexión), errores ICMP Unreachable y Retransmisiones.
            ▪ Vista Dividida: Separa "Todo el Tráfico" de "Anomalías" para una depuración más fácil.



F. Diagnósticos
    • Función: Herramientas de conectividad estándar.
    • Implementación: Wrappers alrededor de comandos del sistema (ping, traceroute, nslookup) con análisis de salida para mostrar en un área de texto de la GUI.
G. Informes
    • Función: Genera un informe HTML de la sesión actual.
    • Implementación: Recopila datos de todos los widgets (resultados de escaneo, registros del sniffer) y los compila en un archivo HTML estilizado utilizando formato de cadenas de Python.

6. Guía para Desarrolladores (Modificando el Código)
Añadir una Nueva Pestaña
    1. Cree un nuevo archivo de widget en src/gui/widgets/ (ej. mi_herramienta.py).
    2. Defina una clase que herede de QWidget.
    3. Impórtela en src/gui/main_window.py.
    4. Añádala a las pestañas: self.tabs.addTab(MiHerramienta(), "Mi Herramienta").
Modificar Escaneos Nmap
    • Edite src/core/scanner.py.
    • El método scan() construye los argumentos del comando Nmap. Puede añadir banderas como -O (Detección de SO) o -sV (Detección de Versión) aquí.
Personalizar el Sniffer
    • Edite src/core/sniffer.py.
    • La función process_packet determina cómo se analizan los paquetes. Puede añadir lógica para detectar payloads específicos (ej. cabeceras HTTP, firmas de malware específicas).
Estilos
    • Edite src/gui/styles.py.
    • La aplicación utiliza QSS (Hojas de Estilo Qt). Puede cambiar colores, fuentes y comportamientos de los widgets aquí.

7. Solución de Problemas
    • "Operation not supported" (Error 95): Ocurre al puentear una interfaz Wi-Fi que no soporta el modo de 4 direcciones.
        ◦ Solución: Use una tarjeta Wi-Fi que soporte modo WDS/Mesh, o use el modo "Wi-Fi AP" en lugar de puentear una conexión cliente.
    • "iw: command not found": Falta la herramienta iw en el sistema.
        ◦ Solución: sudo apt install iw.
    • Sin Resultados de Escaneo:
        ◦ Asegúrese de estar ejecutando como root (a través del lanzador).
        ◦ Verifique si el firewall (ufw) está bloqueando las respuestas.
    • Congelamiento de UI:
        ◦ Un tráfico extremadamente alto en el Sniffer puede ralentizar la UI. Use el filtro BPF para reducir el volumen de captura.

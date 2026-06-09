# NetGuard 2026

> Sistema de monitoreo y seguridad de red en tiempo real — detección de amenazas, gestión de dispositivos y análisis de tráfico con dashboard web interactivo.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat&logo=flask&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.x-00BFFF?style=flat)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=flat&logo=windows&logoColor=white)

---

## Tabla de Contenidos

- [Que es NetGuard](#que-es-netguard)
- [Caracteristicas](#caracteristicas)
- [Arquitectura](#arquitectura)
- [Requisitos](#requisitos)
- [Instalacion](#instalacion)
- [Uso](#uso)
- [Deteccion de Amenazas](#deteccion-de-amenazas)
- [Dashboard](#dashboard)
- [API REST](#api-rest)
- [Pruebas con Kali Linux](#pruebas-con-kali-linux)
- [Estructura del Proyecto](#estructura-del-proyecto)

---

## Que es NetGuard

NetGuard 2026 es un sistema de seguridad de redes desarrollado como proyecto académico para la materia de **Comunicación de Datos**. Captura y analiza el tráfico de red en tiempo real, detecta amenazas automáticamente y las presenta en un dashboard web con alertas visuales.

---

## Caracteristicas

- **Deteccion en tiempo real** de ataques DOS, SYN Flood y Port Scan
- **Gestion de dispositivos** — detecta MACs nuevas y permite aprobarlas o ignorarlas
- **Alertas visuales** con SweetAlert2 — un modal unico por tipo de amenaza
- **Dashboard en vivo** — polling cada 3 segundos a la API Flask
- **Grafica de trafico** en tiempo real (Mbps entrada/salida con psutil)
- **Distribucion de protocolos** — dona con HTTP / TCP / UDP / Otros desde logs
- **Whitelist de IPs** para evitar falsos positivos de CDNs y servidores conocidos
- **Filtros y busqueda** en tablas de dispositivos y alertas

---


## Requisitos

| Componente | Version |
|---|---|
| Python | 3.10+ |
| Npcap (Windows) | Ultima version — [npcap.com](https://npcap.com) |
| Navegador | Chrome / Firefox |
| Permisos | Administrador (para Scapy) |

---

## Instalacion

**1. Ir a la carpeta del proyecto**

```bash
cd NetGuard2026
```

**2. Instalar dependencias**

```bash
pip install -r requirements.txt
```

**3. Instalar Npcap (solo Windows)**

Descargar desde [npcap.com](https://npcap.com/#download) y durante la instalacion activar la opcion **Install Npcap in WinPcap API-compatible mode**.

---

## Uso

Abrir **dos terminales como administrador** y seguir este orden:

**Terminal 1 — Servidor Flask**
```bash
python server.py
```
Salida esperada:
```
[TCP] Puerto 8080
[UDP] Puerto 9090
[HTTP] Puerto 5000
```

**Terminal 2 — Analyzer**
```bash
python analyzer.py
```
Salida esperada:
```
=======================================================
   NETGUARD ANALYZER
=======================================================
   Server     : http://10.129.176.217:5000
   Interfaz   : Intel(R) Wi-Fi 6 AX201 160MHz
   DOS umbral : 300 pkts / 5s
   SYN umbral : 50 pkts / 5s
   Whitelist  : 10 IPs + 14 prefijos
=======================================================
[SNIFFER] Capturando paquetes en tiempo real...
```

**Abrir el Dashboard**

Abrir `index.html` en el navegador o ir a `http://localhost:5000`

### Opciones del Analyzer

```bash
python analyzer.py                              # sniff + log (default)
python analyzer.py --no-log                     # solo sniff de red
python analyzer.py --no-sniff                   # solo lectura de log
python analyzer.py --log logs/otro.log          # log personalizado
python analyzer.py --server http://IP:5000      # servidor remoto
python analyzer.py --iface "Ethernet"           # interfaz manual
```

---

## Deteccion de Amenazas

El analyzer evalua cada paquete capturado en tiempo real con 4 algoritmos simultaneos:

### DOS_ATTACK
```
Umbral : 300 paquetes en 5 segundos (por IP)
Trigger: Paquetes TCP/UDP — excluye SYN puros
Alerta : Modal rojo con IP origen y cantidad de paquetes
```

### SYN_FLOOD
```
Umbral : 50 paquetes SYN en 5 segundos (por IP)
Trigger: Solo flag TCP SYN — handshake incompleto
Alerta : Modal amarillo con IP y cantidad de SYN pkts
```

### PORT_SCAN
```
Umbral : 10 puertos distintos en 5 segundos (por IP)
Trigger: Paquetes SYN a diferentes puertos de destino
Alerta : Modal morado con IP y lista de puertos detectados
```

### NEW_DEVICE
```
Trigger: MAC no vista anteriormente en la red
Accion : Modal azul con IP / MAC / timestamp
         Aceptar -> suma al contador de autorizados
         Ignorar -> marca como ignorado
```

### Cooldown anti-spam
Cada alerta tiene un cooldown de **15 segundos** por tipo + IP para evitar inundar el dashboard.

### Whitelist
Las IPs de Google, Cloudflare, Fastly, Meta y Akamai estan en whitelist por defecto. Para agregar mas:

```python
# En analyzer.py
WHITELIST_IPS = {
    "10.129.176.217",   # tu servidor
    "192.168.1.1",      # agregar aqui
}

WHITELIST_PREFIXES = (
    "142.250.",   # Google
    "172.66.",    # Cloudflare
    # agregar prefijos aqui
)
```

---

## Dashboard

| Seccion | Descripcion |
|---|---|
| **Dashboard** | Vista general — metricas, graficas y resumen de alertas/dispositivos |
| **Dispositivos** | Lista de MACs con IP, timestamp y estado. Filtros: Todos / Autorizados / Pendientes / Ignorados |
| **Alertas** | Registro de eventos. Filtros: DOS / SYN Flood / Port Scan / Nuevo Dispositivo |
| **API Flask** | Muestra configuracion de conexion al servidor |

El dashboard hace polling a la API cada **3 segundos** y actualiza todo automaticamente.

---

## API REST

| Metodo | Endpoint | Descripcion |
|---|---|---|
| `GET` | `/alerts` | Lista de alertas de seguridad |
| `GET` | `/devices` | Dispositivos detectados |
| `GET` | `/authorized` | MACs autorizadas |
| `GET` | `/traffic?limit=60` | Historial de trafico en Mbps |
| `GET` | `/protocol-stats` | Porcentajes HTTP / TCP / UDP / Otros |
| `POST` | `/alert` | Recibir alerta del analyzer |
| `POST` | `/device` | Registrar dispositivo nuevo |
| `POST` | `/approve` | Aprobar dispositivo por MAC |
| `POST` | `/ignore` | Ignorar dispositivo |
| `POST` | `/protocol-stats` | Actualizar estadisticas de protocolo |
| `POST` | `/motion` | Recibir evento de movimiento (ESP32) |

---

## Pruebas con Kali Linux

Comandos para probar cada deteccion desde Kali Linux:

```bash
# PORT SCAN — activa PORT_SCAN
sudo nmap -sS -p 1-500 --min-rate 200 10.129.176.217

# SYN FLOOD — activa SYN_FLOOD
sudo hping3 -S -p 5000 -i u1000 10.129.176.217

# DOS ATTACK — activa DOS_ATTACK (sin flag -S)
sudo hping3 -p 5000 -i u1000 10.129.176.217
```

> Nota: `-i u1000` envia 1000 paquetes/segundo. Asegurate de que la IP de Kali no este en `WHITELIST_IPS`.

---

## Estructura del Proyecto

```
NetGuard2026/
|
+-- server.py           # Servidor Flask — API REST + psutil traffic
+-- analyzer.py         # Scapy sniffer + log reader + deteccion de amenazas
+-- index.html          # Dashboard web
+-- requirements.txt    # Dependencias Python
+-- README.md
|
+-- css/
|   +-- styles.css      # Estilos del dashboard (dark theme)
|
+-- js/
|   +-- api.js          # Polling a Flask + SweetAlert2 por tipo de alerta
|   +-- dashboard.js    # Chart.js, tablas, actualizacion de stats
|   +-- nav.js          # Navegacion entre secciones, relojes, uptime
|   +-- filters.js      # Filtros y busqueda en tablas
|
+-- logs/
    +-- capture.log     # Log de captura de red (para distribucion de protocolos)
```

---

## Autores

- **Jesus Omar Carranza Colin**
- **Daniel Davila Lara**

Universidad Autonoma del Estado de Mexico — Facultad de Ingenieria  
Proyecto Integral de Comunicacion de Datos — Prof. Juan Carlos Escobar Gonzales  
Mayo 2026

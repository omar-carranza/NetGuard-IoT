import time
import json
import argparse
import threading
import requests
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP

# ─── CONFIG ───────────────────────────────────────────────
SERVER_URL     = "http://10.129.176.217:5000"

ALERT_URL      = f"{SERVER_URL}/alert"
DEVICE_URL     = f"{SERVER_URL}/device"
PROTO_STAT_URL = f"{SERVER_URL}/protocol-stats"

# Umbrales de detección
DOS_THRESHOLD       = 100
DOS_WINDOW          = 5

SYN_THRESHOLD       = 50
SYN_WINDOW          = 5

PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW    = 5

ALERT_COOLDOWN      = 15    # segundos entre alertas del mismo tipo/IP
STATS_INTERVAL      = 5     # segundos entre envío de stats de protocolo
# DEFAULT_LOG         = "capture.log"
DEFAULT_LOG = "logs/capture.log"

# ─── State ────────────────────────────────────────────────
authorized_macs  = set()
seen_macs        = set()

dos_counter      = {}
syn_counter      = {}
port_scan_tracker = {}
last_alerts      = {}

# Contadores de protocolo para la dona
proto_counts = {"http": 0, "tcp": 0, "udp": 0, "other": 0}
proto_lock   = threading.Lock()


# ═══════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════

def send_alert(data: dict) -> dict:
    try:
        r = requests.post(ALERT_URL, json=data, timeout=3)
        print(f"[SERVER] {r.status_code}")
        return r.json()
    except Exception as e:
        print(f"[SERVER ERROR] {e}")
        return {}


def send_device(data: dict) -> dict:
    try:
        r = requests.post(DEVICE_URL, json=data, timeout=3)
        print(f"[DEVICE SERVER] {r.status_code}")
        return r.json()
    except Exception as e:
        print(f"[DEVICE ERROR] {e}")
        return {}


def can_alert(alert_key: str) -> bool:
    """Respeta el cooldown para no spamear alertas del mismo tipo+IP."""
    now = time.time()
    if now - last_alerts.get(alert_key, 0) < ALERT_COOLDOWN:
        return False
    last_alerts[alert_key] = now
    return True


# ═══════════════════════════════════════════════════════════
# DETECCIÓN DE DISPOSITIVO NUEVO
# ═══════════════════════════════════════════════════════════

def detect_new_device(packet):
    if not packet.haslayer(Ether):
        return

    mac_src = packet[Ether].src
    mac_dst = packet[Ether].dst

    if mac_src == "ff:ff:ff:ff:ff:ff":
        return
    if mac_src in authorized_macs:
        return
    if mac_src in seen_macs:
        return

    seen_macs.add(mac_src)

    # Intentar obtener IP
    ip_src = None
    if packet.haslayer(IP):
        ip_src = packet[IP].src

    data = {
        "event":     "NEW_DEVICE",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "mac_src":   mac_src,
        "mac_dst":   mac_dst,
        "ip_src":    ip_src,
    }

    print("\n[NEW DEVICE]")
    print(json.dumps(data, indent=4))

    response = send_device(data)
    approved = response.get("approved", False)

    if approved:
        authorized_macs.add(mac_src)
        print(f"[AUTHORIZED] {mac_src}")
    else:
        print(f"[PENDING] {mac_src} — esperando aprobación en dashboard")


# ═══════════════════════════════════════════════════════════
# DETECCIÓN DE PORT SCAN
# ═══════════════════════════════════════════════════════════

def detect_port_scan(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return
    if packet[TCP].flags != "S":
        return

    ip_src    = packet[IP].src
    dst_port  = packet[TCP].dport
    now       = time.time()

    if ip_src not in port_scan_tracker:
        port_scan_tracker[ip_src] = []

    port_scan_tracker[ip_src].append({"port": dst_port, "time": now})
    port_scan_tracker[ip_src] = [
        p for p in port_scan_tracker[ip_src]
        if now - p["time"] <= PORT_SCAN_WINDOW
    ]

    unique_ports = {p["port"] for p in port_scan_tracker[ip_src]}

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:
        alert_key = f"PORTSCAN_{ip_src}"
        if not can_alert(alert_key):
            return

        data = {
            "event":          "PORT_SCAN",
            "timestamp":      datetime.now().strftime("%H:%M:%S"),
            "ip_src":         ip_src,
            "ports_detected": list(unique_ports),
        }
        print("\n[PORT SCAN DETECTED]")
        print(json.dumps(data, indent=4))
        send_alert(data)


# ═══════════════════════════════════════════════════════════
# DETECCIÓN DE SYN FLOOD
# ═══════════════════════════════════════════════════════════

def detect_syn_flood(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return
    if packet[TCP].flags != "S":
        return

    ip_src = packet[IP].src
    now    = time.time()

    if ip_src not in syn_counter:
        syn_counter[ip_src] = []

    syn_counter[ip_src].append(now)
    syn_counter[ip_src] = [
        t for t in syn_counter[ip_src]
        if now - t <= SYN_WINDOW
    ]

    syn_count = len(syn_counter[ip_src])

    if syn_count >= SYN_THRESHOLD:
        alert_key = f"SYNFLOOD_{ip_src}"
        if not can_alert(alert_key):
            return

        data = {
            "event":       "SYN_FLOOD",
            "timestamp":   datetime.now().strftime("%H:%M:%S"),
            "ip_src":      ip_src,
            "syn_packets": syn_count,
        }
        print("\n[SYN FLOOD DETECTED]")
        print(json.dumps(data, indent=4))
        send_alert(data)


# ═══════════════════════════════════════════════════════════
# DETECCIÓN DE DOS
# ═══════════════════════════════════════════════════════════

def detect_dos(packet):
    if not packet.haslayer(IP):
        return
    # Ignorar SYN puros para no confundir con escaneos NMAP
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        return

    ip_src = packet[IP].src
    now    = time.time()

    if ip_src not in dos_counter:
        dos_counter[ip_src] = []

    dos_counter[ip_src].append(now)
    dos_counter[ip_src] = [
        t for t in dos_counter[ip_src]
        if now - t <= DOS_WINDOW
    ]

    packet_count = len(dos_counter[ip_src])

    if packet_count >= DOS_THRESHOLD:
        alert_key = f"DOS_{ip_src}"
        if not can_alert(alert_key):
            return

        data = {
            "event":     "DOS_ATTACK",
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "ip_src":    ip_src,
            "packets":   packet_count,
        }
        print("\n[DOS DETECTED]")
        print(json.dumps(data, indent=4))
        send_alert(data)


# ═══════════════════════════════════════════════════════════
# PROCESADOR PRINCIPAL DE PAQUETES (scapy)
# ═══════════════════════════════════════════════════════════

def process_packet(packet):
    detect_new_device(packet)
    detect_port_scan(packet)
    detect_syn_flood(packet)
    detect_dos(packet)


def run_sniffer():
    print("[SNIFFER] Capturando paquetes en tiempo real... (Ctrl+C para detener)")
    sniff(prn=process_packet, store=0)


# ═══════════════════════════════════════════════════════════
# LOG READER — clasifica líneas del capture.log
# ═══════════════════════════════════════════════════════════

def classify_log_line(line: str) -> str | None:
    """
    Clasifica una línea del log por protocolo.
    Formato esperado:
      10:00:04.438 | HTTP  | Org: ... | Dst: ... | ...
      10:00:04.438 | TCP   | Org: ... | ...
      10:00:04.438 | UDP   | Org: ... | ...
    """
    line = line.strip()
    if not line:
        return None
    parts = line.split("|")
    if len(parts) < 2:
        return None
    proto = parts[1].strip().upper()
    if "HTTP" in proto:
        return "http"
    if "UDP" in proto:
        return "udp"
    if "TCP" in proto:
        return "tcp"
    return "other"


def compute_percentages() -> dict:
    with proto_lock:
        total = sum(proto_counts.values())
        if total == 0:
            return {"http": 0.0, "tcp": 0.0, "udp": 0.0, "other": 0.0, "total": 0}
        return {
            "http":  round(proto_counts["http"]  / total * 100, 2),
            "tcp":   round(proto_counts["tcp"]   / total * 100, 2),
            "udp":   round(proto_counts["udp"]   / total * 100, 2),
            "other": round(proto_counts["other"] / total * 100, 2),
            "total": total,
        }


def send_protocol_stats():
    """Envía estadísticas de protocolo al servidor cada STATS_INTERVAL segundos."""
    while True:
        time.sleep(STATS_INTERVAL)
        stats = compute_percentages()
        if stats["total"] == 0:
            continue
        try:
            r = requests.post(PROTO_STAT_URL, json=stats, timeout=3)
            print(
                f"[PROTO STATS] HTTP={stats['http']}%  TCP={stats['tcp']}%  "
                f"UDP={stats['udp']}%  Otros={stats['other']}%  "
                f"Total={stats['total']}  → {r.status_code}"
            )
        except Exception as e:
            print(f"[PROTO STATS ERROR] {e}")


def tail_log(filepath: str):
    """
    Lee el archivo de log en modo tail-f (espera si no existe todavía).
    Lee desde el INICIO del archivo (historial completo).
    """
    print(f"[LOG] Esperando archivo: {filepath}")
    while True:
        try:
            open(filepath, "r").close()
            break
        except FileNotFoundError:
            time.sleep(2)

    print(f"[LOG] Leyendo: {filepath}")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0)   # leer desde el inicio
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.05)
                continue
            proto = classify_log_line(line)
            if proto:
                with proto_lock:
                    proto_counts[proto] += 1
                total = sum(proto_counts.values())
                if total % 100 == 0:   # log de progreso cada 100 paquetes
                    pcts = compute_percentages()
                    print(
                        f"[LOG] {total} pkts — "
                        f"HTTP={pcts['http']}%  TCP={pcts['tcp']}%  "
                        f"UDP={pcts['udp']}%  Otros={pcts['other']}%"
                    )


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="NetMonitor Analyzer")
    parser.add_argument(
        "--log",
        metavar="FILE",
        default=DEFAULT_LOG,
        help=f"Archivo de log a leer (default: {DEFAULT_LOG})",
    )
    parser.add_argument(
        "--no-log",
        action="store_true",
        help="Desactivar lector de log (solo sniff)",
    )
    parser.add_argument(
        "--no-sniff",
        action="store_true",
        help="Desactivar sniff de red (solo log)",
    )
    parser.add_argument(
        "--server",
        default=SERVER_URL,
        help=f"URL base del servidor Flask (default: {SERVER_URL})",
    )
    args = parser.parse_args()

    # Permitir cambiar la URL desde CLI
    global ALERT_URL, DEVICE_URL, PROTO_STAT_URL
    base = args.server.rstrip("/")
    ALERT_URL      = f"{base}/alert"
    DEVICE_URL     = f"{base}/device"
    PROTO_STAT_URL = f"{base}/protocol-stats"

    use_log   = not args.no_log
    use_sniff = not args.no_sniff

    print("=" * 55)
    print("   NETGUARD ANALYZER")
    print("=" * 55)
    print(f"   Server:  {base}")
    if use_sniff:
        print("   Modo:    Sniff (scapy)")
    if use_log:
        print(f"   Log:     {args.log}  (envío cada {STATS_INTERVAL}s)")
    print("=" * 55)

    threads = []

    if use_log:
        threads.append(threading.Thread(target=tail_log,           args=(args.log,), daemon=True))
        threads.append(threading.Thread(target=send_protocol_stats,                  daemon=True))

    for t in threads:
        t.start()

    try:
        if use_sniff:
            run_sniffer()          # blocking — scapy toma el hilo principal
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[EXIT] Detenido.")
        stats = compute_percentages()
        print(f"\n  Resumen final del log:")
        print(f"  HTTP  : {stats['http']}%")
        print(f"  TCP   : {stats['tcp']}%")
        print(f"  UDP   : {stats['udp']}%")
        print(f"  Otros : {stats['other']}%")
        print(f"  Total : {stats['total']} paquetes")


if __name__ == "__main__":
    main()



# """
# NetMonitor Analyzer
# ===================
# Combina sniff de red (scapy) + lector de log para estadísticas de protocolo.

# Uso:
#   python analyzer.py                              # sniff + log (logs/capture.log)
#   python analyzer.py --log logs/otro.log          # log personalizado
#   python analyzer.py --no-log                     # solo sniff
#   python analyzer.py --no-sniff                   # solo log
#   python analyzer.py --server http://IP:5000      # servidor personalizado
# """

# import time
# import json
# import argparse
# import threading
# import requests
# from datetime import datetime
# from scapy.all import sniff, Ether, IP, TCP

# # ─── CONFIG ───────────────────────────────────────────────
# SERVER_URL = "http://10.129.176.217:5000"

# ALERT_URL      = f"{SERVER_URL}/alert"
# DEVICE_URL     = f"{SERVER_URL}/device"
# PROTO_STAT_URL = f"{SERVER_URL}/protocol-stats"

# # DOS — umbral alto para redes compartidas/hotspot
# DOS_THRESHOLD       = 300
# DOS_WINDOW          = 5

# # SYN FLOOD
# SYN_THRESHOLD       = 50
# SYN_WINDOW          = 5

# # PORT SCAN
# PORT_SCAN_THRESHOLD = 10
# PORT_SCAN_WINDOW    = 5

# # Cooldown entre alertas del mismo tipo+IP
# ALERT_COOLDOWN      = 15

# # Intervalo de envío de estadísticas de protocolo (segundos)
# STATS_INTERVAL      = 5

# # Ruta al log por defecto
# DEFAULT_LOG         = "logs/capture.log"

# # ─── WHITELIST DE IPs ─────────────────────────────────────
# # Estas IPs NUNCA dispararán alertas DOS/SYN/PORT_SCAN
# # Agregar aquí servidores conocidos, CDNs, tu propio servidor, etc.
# WHITELIST_IPS = {
#     # Tu servidor Flask
#     "10.129.176.217",

#     # Google
#     "142.250.65.206",
#     "142.250.65.195",
#     "142.251.46.14",
#     "142.251.157.119",
#     "142.251.210.174",

#     # Cloudflare
#     "172.66.1.120",

#     # Akamai
#     "23.213.185.9",

#     # Fastly / Reddit CDN
#     "151.101.162.250",

#     # Facebook / Meta
#     "157.240.25.60",

#     # Google Cloud
#     "35.186.224.36",
# }

# # Prefijos de rangos completos a ignorar
# # (más eficiente que listar cada IP de Google/CDN)
# WHITELIST_PREFIXES = (
#     "142.250.",    # Google
#     "142.251.",    # Google
#     "172.217.",    # Google
#     "35.186.",     # Google Cloud
#     "34.",         # Google Cloud amplio
#     "151.101.",    # Fastly / CDN
#     "172.66.",     # Cloudflare
#     "172.67.",     # Cloudflare
#     "104.16.",     # Cloudflare
#     "104.17.",     # Cloudflare
#     "157.240.",    # Facebook / Meta
#     "31.13.",      # Facebook / Meta
#     "23.213.",     # Akamai
#     "23.32.",      # Akamai
# )

# # ─── State ────────────────────────────────────────────────
# authorized_macs   = set()
# seen_macs         = set()

# dos_counter       = {}
# syn_counter       = {}
# port_scan_tracker = {}
# last_alerts       = {}

# # Contadores de protocolo para la dona del dashboard
# proto_counts = {"http": 0, "tcp": 0, "udp": 0, "other": 0}
# proto_lock   = threading.Lock()


# # ═══════════════════════════════════════════════════════════
# # HELPERS
# # ═══════════════════════════════════════════════════════════

# def send_alert(data: dict) -> dict:
#     try:
#         r = requests.post(ALERT_URL, json=data, timeout=3)
#         print(f"[SERVER] {r.status_code}")
#         return r.json()
#     except Exception as e:
#         print(f"[SERVER ERROR] {e}")
#         return {}


# def send_device(data: dict) -> dict:
#     try:
#         r = requests.post(DEVICE_URL, json=data, timeout=3)
#         print(f"[DEVICE SERVER] {r.status_code}")
#         return r.json()
#     except Exception as e:
#         print(f"[DEVICE ERROR] {e}")
#         return {}


# def can_alert(alert_key: str) -> bool:
#     """Respeta el cooldown para no spamear alertas del mismo tipo+IP."""
#     now = time.time()
#     if now - last_alerts.get(alert_key, 0) < ALERT_COOLDOWN:
#         return False
#     last_alerts[alert_key] = now
#     return True


# def is_whitelisted(ip: str) -> bool:
#     """Devuelve True si la IP está en whitelist o en un prefijo conocido."""
#     if ip in WHITELIST_IPS:
#         return True
#     if ip.startswith(WHITELIST_PREFIXES):
#         return True
#     return False


# # ═══════════════════════════════════════════════════════════
# # DETECCIÓN DE DISPOSITIVO NUEVO
# # ═══════════════════════════════════════════════════════════

# def detect_new_device(packet):
#     if not packet.haslayer(Ether):
#         return

#     mac_src = packet[Ether].src
#     mac_dst = packet[Ether].dst

#     if mac_src == "ff:ff:ff:ff:ff:ff":
#         return
#     if mac_src in authorized_macs:
#         return
#     if mac_src in seen_macs:
#         return

#     seen_macs.add(mac_src)

#     # Intentar obtener IP del paquete
#     ip_src = None
#     if packet.haslayer(IP):
#         ip_src = packet[IP].src

#     data = {
#         "event":     "NEW_DEVICE",
#         "timestamp": datetime.now().strftime("%H:%M:%S"),
#         "mac_src":   mac_src,
#         "mac_dst":   mac_dst,
#         "ip_src":    ip_src,
#     }

#     print("\n[NEW DEVICE]")
#     print(json.dumps(data, indent=4))

#     response = send_device(data)
#     approved = response.get("approved", False)

#     if approved:
#         authorized_macs.add(mac_src)
#         print(f"[AUTHORIZED] {mac_src}")
#     else:
#         print(f"[PENDING] {mac_src} — esperando aprobación en dashboard")


# # ═══════════════════════════════════════════════════════════
# # DETECCIÓN DE PORT SCAN
# # ═══════════════════════════════════════════════════════════

# def detect_port_scan(packet):
#     if not packet.haslayer(IP) or not packet.haslayer(TCP):
#         return
#     if packet[TCP].flags != "S":
#         return

#     ip_src   = packet[IP].src
#     dst_port = packet[TCP].dport
#     now      = time.time()

#     if is_whitelisted(ip_src):
#         return

#     if ip_src not in port_scan_tracker:
#         port_scan_tracker[ip_src] = []

#     port_scan_tracker[ip_src].append({"port": dst_port, "time": now})
#     port_scan_tracker[ip_src] = [
#         p for p in port_scan_tracker[ip_src]
#         if now - p["time"] <= PORT_SCAN_WINDOW
#     ]

#     unique_ports = {p["port"] for p in port_scan_tracker[ip_src]}

#     if len(unique_ports) >= PORT_SCAN_THRESHOLD:
#         alert_key = f"PORTSCAN_{ip_src}"
#         if not can_alert(alert_key):
#             return

#         data = {
#             "event":          "PORT_SCAN",
#             "timestamp":      datetime.now().strftime("%H:%M:%S"),
#             "ip_src":         ip_src,
#             "ports_detected": list(unique_ports),
#         }
#         print("\n[PORT SCAN DETECTED]")
#         print(json.dumps(data, indent=4))
#         send_alert(data)


# # ═══════════════════════════════════════════════════════════
# # DETECCIÓN DE SYN FLOOD
# # ═══════════════════════════════════════════════════════════

# def detect_syn_flood(packet):
#     if not packet.haslayer(IP) or not packet.haslayer(TCP):
#         return
#     if packet[TCP].flags != "S":
#         return

#     ip_src = packet[IP].src
#     now    = time.time()

#     if is_whitelisted(ip_src):
#         return

#     if ip_src not in syn_counter:
#         syn_counter[ip_src] = []

#     syn_counter[ip_src].append(now)
#     syn_counter[ip_src] = [
#         t for t in syn_counter[ip_src]
#         if now - t <= SYN_WINDOW
#     ]

#     syn_count = len(syn_counter[ip_src])

#     if syn_count >= SYN_THRESHOLD:
#         alert_key = f"SYNFLOOD_{ip_src}"
#         if not can_alert(alert_key):
#             return

#         data = {
#             "event":       "SYN_FLOOD",
#             "timestamp":   datetime.now().strftime("%H:%M:%S"),
#             "ip_src":      ip_src,
#             "syn_packets": syn_count,
#         }
#         print("\n[SYN FLOOD DETECTED]")
#         print(json.dumps(data, indent=4))
#         send_alert(data)


# # ═══════════════════════════════════════════════════════════
# # DETECCIÓN DE DOS
# # ═══════════════════════════════════════════════════════════

# def detect_dos(packet):
#     if not packet.haslayer(IP):
#         return
#     # Ignorar SYN puros para no confundir con escaneos
#     if packet.haslayer(TCP) and packet[TCP].flags == "S":
#         return

#     ip_src = packet[IP].src
#     now    = time.time()

#     if is_whitelisted(ip_src):
#         return

#     if ip_src not in dos_counter:
#         dos_counter[ip_src] = []

#     dos_counter[ip_src].append(now)
#     dos_counter[ip_src] = [
#         t for t in dos_counter[ip_src]
#         if now - t <= DOS_WINDOW
#     ]

#     packet_count = len(dos_counter[ip_src])

#     if packet_count >= DOS_THRESHOLD:
#         alert_key = f"DOS_{ip_src}"
#         if not can_alert(alert_key):
#             return

#         data = {
#             "event":     "DOS_ATTACK",
#             "timestamp": datetime.now().strftime("%H:%M:%S"),
#             "ip_src":    ip_src,
#             "packets":   packet_count,
#         }
#         print("\n[DOS DETECTED]")
#         print(json.dumps(data, indent=4))
#         send_alert(data)


# # ═══════════════════════════════════════════════════════════
# # PROCESADOR PRINCIPAL DE PAQUETES (scapy)
# # ═══════════════════════════════════════════════════════════

# def process_packet(packet):
#     detect_new_device(packet)
#     detect_port_scan(packet)
#     detect_syn_flood(packet)
#     detect_dos(packet)


# def run_sniffer():
#     print("[SNIFFER] Capturando paquetes en tiempo real... (Ctrl+C para detener)")
#     sniff(prn=process_packet, store=0)


# # ═══════════════════════════════════════════════════════════
# # LOG READER — clasifica líneas del capture.log
# # ═══════════════════════════════════════════════════════════

# def classify_log_line(line: str):
#     """
#     Clasifica una línea del log por protocolo.
#     Formato esperado:
#       10:00:04.438 | HTTP  | Org: ... | Dst: ... | ...
#       10:00:04.438 | TCP   | Org: ... | ...
#       10:00:04.438 | UDP   | Org: ... | ...
#     """
#     line = line.strip()
#     if not line:
#         return None
#     parts = line.split("|")
#     if len(parts) < 2:
#         return None
#     proto = parts[1].strip().upper()
#     if "HTTP" in proto:
#         return "http"
#     if "UDP" in proto:
#         return "udp"
#     if "TCP" in proto:
#         return "tcp"
#     return "other"


# def compute_percentages() -> dict:
#     with proto_lock:
#         total = sum(proto_counts.values())
#         if total == 0:
#             return {"http": 0.0, "tcp": 0.0, "udp": 0.0, "other": 0.0, "total": 0}
#         return {
#             "http":  round(proto_counts["http"]  / total * 100, 2),
#             "tcp":   round(proto_counts["tcp"]   / total * 100, 2),
#             "udp":   round(proto_counts["udp"]   / total * 100, 2),
#             "other": round(proto_counts["other"] / total * 100, 2),
#             "total": total,
#         }


# def send_protocol_stats():
#     """Envía estadísticas de protocolo al servidor cada STATS_INTERVAL segundos."""
#     while True:
#         time.sleep(STATS_INTERVAL)
#         stats = compute_percentages()
#         if stats["total"] == 0:
#             continue
#         try:
#             r = requests.post(PROTO_STAT_URL, json=stats, timeout=3)
#             print(
#                 f"[PROTO STATS] HTTP={stats['http']}%  TCP={stats['tcp']}%  "
#                 f"UDP={stats['udp']}%  Otros={stats['other']}%  "
#                 f"Total={stats['total']}  → {r.status_code}"
#             )
#         except Exception as e:
#             print(f"[PROTO STATS ERROR] {e}")


# def tail_log(filepath: str):
#     """
#     Lee el archivo de log en modo tail-f.
#     Espera si el archivo no existe todavía.
#     Lee desde el INICIO del archivo (historial completo + nuevas líneas).
#     """
#     print(f"[LOG] Esperando archivo: {filepath}")
#     while True:
#         try:
#             open(filepath, "r").close()
#             break
#         except FileNotFoundError:
#             time.sleep(2)

#     print(f"[LOG] Leyendo: {filepath}")
#     with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
#         f.seek(0)
#         while True:
#             line = f.readline()
#             if not line:
#                 time.sleep(0.05)
#                 continue
#             proto = classify_log_line(line)
#             if proto:
#                 with proto_lock:
#                     proto_counts[proto] += 1
#                 total = sum(proto_counts.values())
#                 if total % 100 == 0:
#                     pcts = compute_percentages()
#                     print(
#                         f"[LOG] {total} pkts — "
#                         f"HTTP={pcts['http']}%  TCP={pcts['tcp']}%  "
#                         f"UDP={pcts['udp']}%  Otros={pcts['other']}%"
#                     )


# # ═══════════════════════════════════════════════════════════
# # MAIN
# # ═══════════════════════════════════════════════════════════

# def main():
#     parser = argparse.ArgumentParser(description="NetMonitor Analyzer")
#     parser.add_argument(
#         "--log",
#         metavar="FILE",
#         default=DEFAULT_LOG,
#         help=f"Archivo de log (default: {DEFAULT_LOG})",
#     )
#     parser.add_argument(
#         "--no-log",
#         action="store_true",
#         help="Desactivar lector de log (solo sniff)",
#     )
#     parser.add_argument(
#         "--no-sniff",
#         action="store_true",
#         help="Desactivar sniff de red (solo log)",
#     )
#     parser.add_argument(
#         "--server",
#         default=SERVER_URL,
#         help=f"URL base del servidor Flask (default: {SERVER_URL})",
#     )
#     args = parser.parse_args()

#     # Permitir cambiar la URL desde CLI
#     global ALERT_URL, DEVICE_URL, PROTO_STAT_URL
#     base           = args.server.rstrip("/")
#     ALERT_URL      = f"{base}/alert"
#     DEVICE_URL     = f"{base}/device"
#     PROTO_STAT_URL = f"{base}/protocol-stats"

#     use_log   = not args.no_log
#     use_sniff = not args.no_sniff

#     print("=" * 55)
#     print("   NETGUARD ANALYZER")
#     print("=" * 55)
#     print(f"   Server     : {base}")
#     print(f"   DOS umbral : {DOS_THRESHOLD} pkts / {DOS_WINDOW}s")
#     print(f"   SYN umbral : {SYN_THRESHOLD} pkts / {SYN_WINDOW}s")
#     print(f"   Whitelist  : {len(WHITELIST_IPS)} IPs + {len(WHITELIST_PREFIXES)} prefijos")
#     if use_sniff:
#         print("   Sniff      : activo")
#     if use_log:
#         print(f"   Log        : {args.log}  (envío cada {STATS_INTERVAL}s)")
#     print("=" * 55)

#     threads = []

#     if use_log:
#         threads.append(threading.Thread(
#             target=tail_log, args=(args.log,), daemon=True, name="log-reader"
#         ))
#         threads.append(threading.Thread(
#             target=send_protocol_stats, daemon=True, name="proto-stats"
#         ))

#     for t in threads:
#         t.start()

#     try:
#         if use_sniff:
#             run_sniffer()       # blocking — scapy toma el hilo principal
#         else:
#             while True:
#                 time.sleep(1)
#     except KeyboardInterrupt:
#         print("\n[EXIT] Detenido.")
#         stats = compute_percentages()
#         print(f"\n  Resumen final del log:")
#         print(f"  HTTP  : {stats['http']}%")
#         print(f"  TCP   : {stats['tcp']}%")
#         print(f"  UDP   : {stats['udp']}%")
#         print(f"  Otros : {stats['other']}%")
#         print(f"  Total : {stats['total']} paquetes")


# if __name__ == "__main__":
#     main()

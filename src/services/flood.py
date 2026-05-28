# from scapy.all import sniff, Ether, IP, TCP
# from datetime import datetime
# import requests
# import time
# import json

# # ============================================
# # CONFIG
# # ============================================

# SERVER_URL = "http://192.168.1.6:5000/alert"

# # DOS
# DOS_THRESHOLD = 40
# DOS_TIME_WINDOW = 5

# # PORT SCAN
# PORT_SCAN_THRESHOLD = 10
# PORT_SCAN_WINDOW = 5

# # ============================================
# # VARIABLES
# # ============================================

# authorized_macs = set()
# seen_macs = set()

# ip_packet_counter = {}

# port_scan_tracker = {}

# # ============================================
# # ENVIAR AL SERVIDOR
# # ============================================

# def send_to_server(data):

#     try:

#         response = requests.post(
#             SERVER_URL,
#             json=data,
#             timeout=3
#         )

#         print(f"[SERVER] {response.status_code}")

#         return response.json()

#     except Exception as e:

#         print(f"[SERVER ERROR] {e}")

#         return {}

# # ============================================
# # NUEVO DISPOSITIVO
# # ============================================

# def detect_new_device(packet):

#     if not packet.haslayer(Ether):
#         return

#     mac_src = packet[Ether].src
#     mac_dst = packet[Ether].dst

#     # Ignorar broadcast
#     if mac_src == "ff:ff:ff:ff:ff:ff":
#         return

#     # Ya autorizado
#     if mac_src in authorized_macs:
#         return

#     # Ya visto
#     if mac_src in seen_macs:
#         return

#     seen_macs.add(mac_src)

#     data = {

#         "event": "NEW_DEVICE",

#         "timestamp": datetime.now().strftime("%H:%M:%S"),

#         "mac_src": mac_src,

#         "mac_dst": mac_dst

#     }

#     print("\n[NEW DEVICE]")
#     print(json.dumps(data, indent=4))

#     response = send_to_server(data)

#     approved = response.get("approved", False)

#     if approved:

#         authorized_macs.add(mac_src)

#         print(f"[AUTHORIZED] {mac_src}")

#     else:

#         print(f"[INTRUDER] {mac_src}")

# # ============================================
# # DETECTAR DOS
# # ============================================

# def detect_dos(packet):

#     if not packet.haslayer(IP):
#         return

#     ip_src = packet[IP].src

#     current_time = time.time()

#     if ip_src not in ip_packet_counter:

#         ip_packet_counter[ip_src] = []

#     ip_packet_counter[ip_src].append(current_time)

#     # Mantener solo tiempos recientes
#     ip_packet_counter[ip_src] = [

#         t for t in ip_packet_counter[ip_src]

#         if current_time - t <= DOS_TIME_WINDOW

#     ]

#     packet_count = len(ip_packet_counter[ip_src])

#     if packet_count >= DOS_THRESHOLD:

#         data = {

#             "event": "DOS_ATTACK",

#             "timestamp": datetime.now().strftime("%H:%M:%S"),

#             "ip_src": ip_src,

#             "packets": packet_count,

#             "window": DOS_TIME_WINDOW

#         }

#         print("\n[DOS DETECTED]")
#         print(json.dumps(data, indent=4))

#         send_to_server(data)

#         # Reiniciar contador
#         ip_packet_counter[ip_src] = []

# # ============================================
# # DETECTAR PORT SCAN
# # ============================================

# def detect_port_scan(packet):

#     if not packet.haslayer(IP):
#         return

#     if not packet.haslayer(TCP):
#         return

#     ip_src = packet[IP].src
#     dst_port = packet[TCP].dport

#     current_time = time.time()

#     if ip_src not in port_scan_tracker:

#         port_scan_tracker[ip_src] = []

#     port_scan_tracker[ip_src].append({

#         "port": dst_port,
#         "time": current_time

#     })

#     # Mantener solo puertos recientes
#     port_scan_tracker[ip_src] = [

#         p for p in port_scan_tracker[ip_src]

#         if current_time - p["time"] <= PORT_SCAN_WINDOW

#     ]

#     unique_ports = set(

#         p["port"]

#         for p in port_scan_tracker[ip_src]

#     )

#     if len(unique_ports) >= PORT_SCAN_THRESHOLD:

#         data = {

#             "event": "PORT_SCAN",

#             "timestamp": datetime.now().strftime("%H:%M:%S"),

#             "ip_src": ip_src,

#             "ports_detected": list(unique_ports)

#         }

#         print("\n[PORT SCAN DETECTED]")
#         print(json.dumps(data, indent=4))

#         send_to_server(data)

#         # Reiniciar
#         port_scan_tracker[ip_src] = []

# # ============================================
# # PROCESAR PAQUETE
# # ============================================

# def process_packet(packet):

#     detect_new_device(packet)

#     detect_dos(packet)

#     detect_port_scan(packet)

# # ============================================
# # MAIN
# # ============================================

# def main():

#     print("=" * 50)
#     print(" NETGUARD ANALYZER ")
#     print("=" * 50)

#     sniff(

#         prn=process_packet,
#         store=0

#     )

# if __name__ == "__main__":

#     main()
from scapy.all import sniff, Ether, IP, TCP
from datetime import datetime
import requests
import time
import json

# ============================================
# CONFIG
# ============================================

SERVER_URL = "http://192.168.1.6:5000/alert"

# DOS
DOS_THRESHOLD = 100
DOS_WINDOW = 5

# SYN FLOOD
SYN_THRESHOLD = 50
SYN_WINDOW = 5

# PORT SCAN
PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW = 5

# Evitar spam de alertas
ALERT_COOLDOWN = 15

# ============================================
# VARIABLES
# ============================================

authorized_macs = set()
seen_macs = set()

dos_counter = {}
syn_counter = {}
port_scan_tracker = {}

last_alerts = {}

# ============================================
# ENVIAR AL SERVIDOR
# ============================================

def send_to_server(data):

    try:

        response = requests.post(
            SERVER_URL,
            json=data,
            timeout=3
        )

        print(f"[SERVER] {response.status_code}")

        return response.json()

    except Exception as e:

        print(f"[SERVER ERROR] {e}")

        return {}

# ============================================
# VALIDAR COOLDOWN
# ============================================

def can_alert(alert_key):

    current_time = time.time()

    last_time = last_alerts.get(alert_key, 0)

    if current_time - last_time < ALERT_COOLDOWN:
        return False

    last_alerts[alert_key] = current_time

    return True

# ============================================
# NUEVO DISPOSITIVO
# ============================================

def detect_new_device(packet):

    if not packet.haslayer(Ether):
        return

    mac_src = packet[Ether].src
    mac_dst = packet[Ether].dst

    # Ignorar broadcast
    if mac_src == "ff:ff:ff:ff:ff:ff":
        return

    # Ya autorizado
    if mac_src in authorized_macs:
        return

    # Ya visto
    if mac_src in seen_macs:
        return

    seen_macs.add(mac_src)

    data = {

        "event": "NEW_DEVICE",

        "timestamp": datetime.now().strftime("%H:%M:%S"),

        "mac_src": mac_src,

        "mac_dst": mac_dst

    }

    print("\n[NEW DEVICE]")
    print(json.dumps(data, indent=4))

    response = send_to_server(data)

    approved = response.get("approved", False)

    if approved:

        authorized_macs.add(mac_src)

        print(f"[AUTHORIZED] {mac_src}")

    else:

        print(f"[INTRUDER] {mac_src}")

# ============================================
# DETECTAR PORT SCAN
# ============================================

def detect_port_scan(packet):

    if not packet.haslayer(IP):
        return

    if not packet.haslayer(TCP):
        return

    # Solo SYN
    if packet[TCP].flags != "S":
        return

    ip_src = packet[IP].src
    dst_port = packet[TCP].dport

    current_time = time.time()

    if ip_src not in port_scan_tracker:

        port_scan_tracker[ip_src] = []

    port_scan_tracker[ip_src].append({

        "port": dst_port,
        "time": current_time

    })

    # Mantener recientes
    port_scan_tracker[ip_src] = [

        p for p in port_scan_tracker[ip_src]

        if current_time - p["time"] <= PORT_SCAN_WINDOW

    ]

    unique_ports = set(

        p["port"]

        for p in port_scan_tracker[ip_src]

    )

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:

        alert_key = f"PORTSCAN_{ip_src}"

        if not can_alert(alert_key):
            return

        data = {

            "event": "PORT_SCAN",

            "timestamp": datetime.now().strftime("%H:%M:%S"),

            "ip_src": ip_src,

            "ports_detected": list(unique_ports)

        }

        print("\n[PORT SCAN DETECTED]")
        print(json.dumps(data, indent=4))

        send_to_server(data)

# ============================================
# DETECTAR SYN FLOOD
# ============================================

def detect_syn_flood(packet):

    if not packet.haslayer(IP):
        return

    if not packet.haslayer(TCP):
        return

    # Solo SYN
    if packet[TCP].flags != "S":
        return

    ip_src = packet[IP].src

    current_time = time.time()

    if ip_src not in syn_counter:

        syn_counter[ip_src] = []

    syn_counter[ip_src].append(current_time)

    syn_counter[ip_src] = [

        t for t in syn_counter[ip_src]

        if current_time - t <= SYN_WINDOW

    ]

    syn_count = len(syn_counter[ip_src])

    if syn_count >= SYN_THRESHOLD:

        alert_key = f"SYNFLOOD_{ip_src}"

        if not can_alert(alert_key):
            return

        data = {

            "event": "SYN_FLOOD",

            "timestamp": datetime.now().strftime("%H:%M:%S"),

            "ip_src": ip_src,

            "syn_packets": syn_count

        }

        print("\n[SYN FLOOD DETECTED]")
        print(json.dumps(data, indent=4))

        send_to_server(data)

# ============================================
# DETECTAR DOS
# ============================================

def detect_dos(packet):

    if not packet.haslayer(IP):
        return

    # Ignorar SYN para evitar confundir NMAP
    if packet.haslayer(TCP):

        if packet[TCP].flags == "S":
            return

    ip_src = packet[IP].src

    current_time = time.time()

    if ip_src not in dos_counter:

        dos_counter[ip_src] = []

    dos_counter[ip_src].append(current_time)

    dos_counter[ip_src] = [

        t for t in dos_counter[ip_src]

        if current_time - t <= DOS_WINDOW

    ]

    packet_count = len(dos_counter[ip_src])

    if packet_count >= DOS_THRESHOLD:

        alert_key = f"DOS_{ip_src}"

        if not can_alert(alert_key):
            return

        data = {

            "event": "DOS_ATTACK",

            "timestamp": datetime.now().strftime("%H:%M:%S"),

            "ip_src": ip_src,

            "packets": packet_count

        }

        print("\n[DOS DETECTED]")
        print(json.dumps(data, indent=4))

        send_to_server(data)

# ============================================
# PROCESAR PAQUETE
# ============================================

def process_packet(packet):

    detect_new_device(packet)

    detect_port_scan(packet)

    detect_syn_flood(packet)

    detect_dos(packet)

# ============================================
# MAIN
# ============================================

def main():

    print("=" * 50)
    print(" NETGUARD ANALYZER ")
    print("=" * 50)

    sniff(

        prn=process_packet,
        store=0

    )

if __name__ == "__main__":

    main()
# import time

# CAPTURE_LOG = "logs/capture.log"

# FLOOD_THRESHOLD = 5
# TIME_WINDOW = 5

# contador_ips = {}

# def generar_alerta(ip, cantidad):

#     print("\n🚨 FLOOD DETECTADO 🚨")

#     print(

#         f"IP: {ip} | "
#         f"{cantidad} paquetes "
#         f"en {TIME_WINDOW} segundos"

#     )


# def analizar_linea(linea):

#     try:
#         if not linea.strip():
#             return

#         partes = linea.split("|")

#         if len(partes) < 3:

#             return

#         ip_src = (
#             partes[2]
#             .replace("Org:", "")
#             .strip()
#         )

#         print(f"[PAQUETE] {ip_src}")

#         current_time = time.time()

#         if ip_src not in contador_ips:

#             contador_ips[ip_src] = []

#         contador_ips[ip_src].append(current_time)

#         contador_ips[ip_src] = [

#             t for t in contador_ips[ip_src]

#             if current_time - t <= TIME_WINDOW

#         ]
#         cantidad = len(contador_ips[ip_src])

#         print(

#             f"[{ip_src}] "
#             f"{cantidad} paquetes recientes"

#         )

#         if cantidad >= FLOOD_THRESHOLD:

#             generar_alerta(ip_src, cantidad)

#             # REINICIAR CONTADOR

#             contador_ips[ip_src] = []

#     except Exception as e:

#         print(f"ERROR: {e}")

# # ============================================
# # MONITOREAR LOG
# # ============================================

# def monitor_log():

#     print("=" * 60)

#     print(" NETGUARD FLOOD ANALYZER ")

#     print("=" * 60)

#     print("\nEsperando paquetes...\n")

#     with open(

#         CAPTURE_LOG,
#         "r",
#         encoding="utf-8"

#     ) as file:

#         # LEER DESDE EL INICIO

#         while True:

#             linea = file.readline()

#             if not linea:

#                 time.sleep(0.1)

#                 continue

#             analizar_linea(linea)

# if __name__ == "__main__":

#     monitor_log()

# from scapy.all import sniff, Ether
# import requests
# import json
# from datetime import datetime

# # API DASHBOARD
# API_URL = "http://192.168.1.6:5000/device"

# # MACS YA DETECTADAS
# macs_detectadas = set()

# def enviar_dashboard(data):

#     try:

#         response = requests.post(

#             API_URL,
#             json=data,
#             timeout=3

#         )

#         print(f"[API] Status: {response.status_code}")

#     except Exception as e:

#         print(f"[API ERROR] {e}")

# def procesar_paquete(packet):

#     if not packet.haslayer(Ether):
#         return

#     mac_src = packet[Ether].src
#     mac_dst = packet[Ether].dst

#     # Ignorar broadcast
#     if mac_src == "ff:ff:ff:ff:ff:ff":
#         return

#     # Ignorar repetidos
#     if mac_src in macs_detectadas:
#         return

#     macs_detectadas.add(mac_src)

#     timestamp = datetime.now().strftime("%H:%M:%S")

#     data = {

#         "event": "NEW_DEVICE",

#         "timestamp": timestamp,

#         "mac_src": mac_src,

#         "mac_dst": mac_dst

#     }

#     print("\n[NEW DEVICE DETECTED]")

#     print(json.dumps(data, indent=4))

#     enviar_dashboard(data)

# def main():

#     print("=" * 50)
#     print(" NETGUARD DEVICE ANALYZER ")
#     print("=" * 50)

#     sniff(

#         prn=procesar_paquete,
#         store=0

#     )

# if __name__ == "__main__":

#     main()

from scapy.all import sniff, Ether
import requests
import json
from datetime import datetime

API_URL = "http://192.168.1.6:5000/device"

# MACS APROBADAS LOCALMENTE
authorized_macs = set()

# MACS YA ANALIZADAS
seen_macs = set()

def send_to_server(data):

    try:

        response = requests.post(

            API_URL,
            json=data,
            timeout=3

        )

        response_data = response.json()

        approved = response_data.get("approved")

        return approved

    except Exception as e:

        print(f"[API ERROR] {e}")

        return False

def process_packet(packet):

    if not packet.haslayer(Ether):
        return

    mac_src = packet[Ether].src
    mac_dst = packet[Ether].dst

    # Ignorar broadcast
    if mac_src == "ff:ff:ff:ff:ff:ff":
        return

    # Ignorar ya autorizadas
    if mac_src in authorized_macs:
        return

    # Ignorar repetidas ya analizadas
    if mac_src in seen_macs:
        return

    seen_macs.add(mac_src)

    timestamp = datetime.now().strftime("%H:%M:%S")

    data = {

        "event": "NEW_DEVICE",

        "timestamp": timestamp,

        "mac_src": mac_src,

        "mac_dst": mac_dst

    }

    print("\n[NEW DEVICE DETECTED]")

    print(json.dumps(data, indent=4))

    approved = send_to_server(data)

    if approved:

        authorized_macs.add(mac_src)

        print(f"\n[AUTHORIZED] {mac_src}")

    else:

        print(f"\n[INTRUDER] {mac_src}")

def main():

    print("=" * 50)
    print(" NETGUARD DEVICE ANALYZER ")
    print("=" * 50)

    sniff(

        prn=process_packet,
        store=0

    )

if __name__ == "__main__":

    main()
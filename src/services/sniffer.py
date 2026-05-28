from scapy.all import sniff, TCP, UDP, IP, Raw
import datetime
import os

INTERFACE = "Wi-Fi"

# HTTP
TARGET_IP = "10.129.176.217"
TARGET_PORT_HTTP = 5000
TARGET_PATH = "/motion"

# LOGS
LOG_DIR = "logs"
LOG_FILE = f"{LOG_DIR}/capture.log"

# CREAR CARPETA SI NO EXISTE
os.makedirs(LOG_DIR, exist_ok=True)
max_packet_size = 0

def procesar_paquete(packet):

    global max_packet_size

    if not packet.haslayer(IP):
        return

    # TIMESTAMP
    timestamp_humano = datetime.datetime.fromtimestamp(
        packet.time
    ).strftime('%H:%M:%S.%f')[:-3]

    # DATOS IP
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst

    # TAMAÑO DEL PAQUETE
    packet_size = len(packet)

    # ACTUALIZAR MAXIMO
    if packet_size > max_packet_size:
        max_packet_size = packet_size

    # VARIABLES
    proto = "OTRO"
    sport = "-"
    dport = "-"
    info = "Sin payload"
    es_valido = False

    # TCP
    if packet.haslayer(TCP):

        sport = packet[TCP].sport
        dport = packet[TCP].dport

        if sport == 8080 or dport == 8080:
            proto = "TCP"
            es_valido = True

        elif dport == TARGET_PORT_HTTP and ip_dst == TARGET_IP:

            if packet.haslayer(Raw):

                try:

                    payload_raw = packet[Raw].load.decode(
                        'utf-8',
                        errors='ignore'
                    ).strip()

                except:

                    payload_raw = str(packet[Raw].load)

                if TARGET_PATH in payload_raw:

                    proto = "HTTP"

                    es_valido = True

                    info = " ".join(payload_raw.split())[:100]

    # UDP
    elif packet.haslayer(UDP):

        sport = packet[UDP].sport
        dport = packet[UDP].dport

        if sport == 9090 or dport == 9090:

            proto = "UDP"

            es_valido = True

    # PAYLOAD GENERAL
    if packet.haslayer(Raw) and info == "Sin payload":

        try:

            payload_raw = packet[Raw].load.decode(
                'utf-8',
                errors='ignore'
            ).strip()

        except:

            payload_raw = str(packet[Raw].load)

        info = " ".join(payload_raw.split())[:100]

    # MOSTRAR Y GUARDAR
    if es_valido:

        linea = (
            f"{timestamp_humano} | "
            f"{proto:<5} | "
            f"Org: {ip_src:<15} | "
            f"Dst: {ip_dst:<15} | "
            f"Org: {sport:<5} | "
            f"Dst: {dport:<5} | "
            f"Bytes: {packet_size:<5} | "
            f"MAX: {max_packet_size:<5} | "
            f"Pld: {info}"
        )

        # print(linea)
        with open(LOG_FILE, "a", encoding="utf-8") as log:

            log.write(linea + "\n")

def main():
    print("")
    print("NETGUARD-IOT SNIFFER ")
    print("")
    print("Capturando tráfico IoT....\n")

    # FILTRO BPF
    filtro_bpf = "tcp port 8080 or udp port 9090 or tcp port 5000"

    try:

        sniff(
            iface=INTERFACE,
            filter=filtro_bpf,
            prn=procesar_paquete,
            store=0
        )

    except KeyboardInterrupt:
        print("\nCaptura detenida")


if __name__ == "__main__":
    main()
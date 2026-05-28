# import socket
# import threading
# from flask import Flask, request, jsonify

# TCP_HOST = "0.0.0.0"
# TCP_PORT = 8080

# UDP_HOST = "0.0.0.0"
# UDP_PORT = 9090

# HTTP_PORT = 5000

# app = Flask(__name__)

# # ENDPOINT HTTP
# @app.route('/motion', methods=['POST'])
# def motion():

#     data = request.json
#     print("\n[HTTP] Datos recibidos:")
#     print(data)

#     return jsonify({
#         "status": "OK"
#     })

# # SERVIDOR TCP
# def tcp_server():

#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((TCP_HOST, TCP_PORT))
#     server.listen()

#     print(f"\n[TCP] Escuchando en puerto {TCP_PORT}")

#     while True:

#         client, addr = server.accept()
#         print(f"\n[TCP] Conexion desde {addr}")

#         data = client.recv(1024).decode()
#         print("[TCP] Datos recibidos:")
#         print(data)

#         client.send(b"ACK\n")
#         client.close()

# # SERVIDOR UDP
# def udp_server():

#     server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     server.bind((UDP_HOST, UDP_PORT))

#     print(f"\n[UDP] Escuchando en puerto {UDP_PORT}")

#     while True:

#         data, addr = server.recvfrom(1024)
#         print(f"\n[UDP] Paquete desde {addr}")
#         print(data.decode())


# if __name__ == '__main__':

#     tcp_thread = threading.Thread(target=tcp_server)    # Hilo que inicia el socket TCP
#     tcp_thread.daemon = True
#     tcp_thread.start()

#     udp_thread = threading.Thread(target=udp_server)    # Hilo que inicia el socket UDP
#     udp_thread.daemon = True
#     udp_thread.start()

#     print(f"\n[HTTP] Flask ejecutandose en puerto {HTTP_PORT}") # Inicia el servidor Flask

#     app.run(
#         host='0.0.0.0',
#         port=HTTP_PORT,
#         debug=False
#     )


# import socket
# import threading
# from flask import Flask, request, jsonify

# TCP_HOST = "0.0.0.0"
# TCP_PORT = 8080

# UDP_HOST = "0.0.0.0"
# UDP_PORT = 9090

# HTTP_PORT = 5000

# app = Flask(__name__)

# # MACS AUTORIZADAS
# authorized_macs = [

#     "94:e3:ee:45:d4:86"

# ]

# # DISPOSITIVOS DETECTADOS
# devices_detected = []

# # ENDPOINT ESP32 HTTP
# @app.route('/motion', methods=['POST'])
# def motion():

#     data = request.json

#     print("\n[HTTP] Datos recibidos:")
#     print(data)

#     return jsonify({
#         "status": "OK"
#     })

# # ENDPOINT ANALYZER
# @app.route('/device', methods=['POST'])
# def receive_device():

#     data = request.get_json()

#     mac_src = data.get("mac_src")

#     approved = mac_src in authorized_macs

#     device_info = {

#         "timestamp": data.get("timestamp"),

#         "event": data.get("event"),

#         "mac_src": mac_src,

#         "mac_dst": data.get("mac_dst"),

#         "approved": approved

#     }

#     devices_detected.append(device_info)

#     print("\n[DEVICE RECEIVED]")
#     print(device_info)

#     return jsonify({

#         "approved": approved

#     })

# # APROBAR DISPOSITIVO
# @app.route('/approve', methods=['POST'])
# def approve_device():

#     data = request.get_json()

#     mac = data.get("mac")

#     if mac not in authorized_macs:

#         authorized_macs.append(mac)

#     print(f"\n[DEVICE APPROVED] {mac}")

#     return jsonify({

#         "status": "approved",

#         "mac": mac

#     })

# # OBTENER DISPOSITIVOS
# @app.route('/devices', methods=['GET'])
# def get_devices():

#     return jsonify(devices_detected)

# # OBTENER WHITELIST
# @app.route('/authorized', methods=['GET'])
# def get_authorized():

#     return jsonify(authorized_macs)

# # SERVIDOR TCP
# def tcp_server():

#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#     server.bind((TCP_HOST, TCP_PORT))

#     server.listen()

#     print(f"\n[TCP] Escuchando en puerto {TCP_PORT}")

#     while True:

#         client, addr = server.accept()

#         print(f"\n[TCP] Conexion desde {addr}")

#         data = client.recv(1024).decode()

#         print("[TCP] Datos recibidos:")
#         print(data)

#         client.send(b"ACK\n")

#         client.close()

# # SERVIDOR UDP
# def udp_server():

#     server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#     server.bind((UDP_HOST, UDP_PORT))

#     print(f"\n[UDP] Escuchando en puerto {UDP_PORT}")

#     while True:

#         data, addr = server.recvfrom(1024)

#         print(f"\n[UDP] Paquete desde {addr}")

#         print(data.decode())

# if __name__ == '__main__':

#     tcp_thread = threading.Thread(target=tcp_server)

#     tcp_thread.daemon = True

#     tcp_thread.start()

#     udp_thread = threading.Thread(target=udp_server)

#     udp_thread.daemon = True

#     udp_thread.start()

#     print(f"\n[HTTP] Flask ejecutandose en puerto {HTTP_PORT}")

#     app.run(

#         host='0.0.0.0',

#         port=HTTP_PORT,

#         debug=False

#     )




import socket
import threading
from flask import Flask, request, jsonify

TCP_HOST = "0.0.0.0"
TCP_PORT = 8080

UDP_HOST = "0.0.0.0"
UDP_PORT = 9090

HTTP_PORT = 5000

app = Flask(__name__)

authorized_macs = [

    "94:e3:ee:45:d4:86"

]

devices_detected = []

alerts_detected = []

# ESP32 HTTP
@app.route('/motion', methods=['POST'])
def motion():

    data = request.json

    print("\n[HTTP]")
    print(data)

    return jsonify({
        "status": "OK"
    })

# ANALYZER DEVICE
@app.route('/device', methods=['POST'])
def receive_device():

    data = request.get_json()

    mac_src = data.get("mac_src")

    approved = mac_src in authorized_macs

    device_info = {

        "timestamp": data.get("timestamp"),

        "event": data.get("event"),

        "mac_src": mac_src,

        "mac_dst": data.get("mac_dst"),

        "approved": approved

    }

    devices_detected.append(device_info)

    print("\n[DEVICE]")
    print(device_info)

    return jsonify({

        "approved": approved

    })

# ANALYZER ALERTS
@app.route('/alert', methods=['POST'])
def receive_alert():

    data = request.get_json()

    event = data.get("event")

    alert_info = {

        "timestamp": data.get("timestamp"),

        "event": event,

        "ip_src": data.get("ip_src")

    }

    # DOS
    if event == "DOS_ATTACK":

        alert_info["packets"] = data.get("packets")

    # SYN FLOOD
    elif event == "SYN_FLOOD":

        alert_info["syn_packets"] = data.get("syn_packets")

    # PORT SCAN
    elif event == "PORT_SCAN":

        alert_info["ports_detected"] = data.get("ports_detected")

    alerts_detected.append(alert_info)

    print(f"\n[{event}]")
    print(alert_info)

    return jsonify({

        "status": "received",

        "event": event

    })

# APROBAR DISPOSITIVO
@app.route('/approve', methods=['POST'])
def approve_device():

    data = request.get_json()

    mac = data.get("mac")

    if mac not in authorized_macs:

        authorized_macs.append(mac)

    print(f"\n[APPROVED] {mac}")

    return jsonify({

        "status": "approved",

        "mac": mac

    })

# DEVICES
@app.route('/devices', methods=['GET'])
def get_devices():

    return jsonify(devices_detected)

# ALERTS
@app.route('/alerts', methods=['GET'])
def get_alerts():

    return jsonify(alerts_detected)

# AUTHORIZED MACS
@app.route('/authorized', methods=['GET'])
def get_authorized():

    return jsonify(authorized_macs)

# TCP SERVER
def tcp_server():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.bind((TCP_HOST, TCP_PORT))

    server.listen()

    print(f"\n[TCP] Puerto {TCP_PORT}")

    while True:

        client, addr = server.accept()

        print(f"\n[TCP] Conexion {addr}")

        data = client.recv(1024).decode()

        print(data)

        client.send(b"ACK\n")

        client.close()

# UDP SERVER
def udp_server():

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    server.bind((UDP_HOST, UDP_PORT))

    print(f"\n[UDP] Puerto {UDP_PORT}")

    while True:

        data, addr = server.recvfrom(1024)

        print(f"\n[UDP] {addr}")

        print(data.decode())

if __name__ == '__main__':

    tcp_thread = threading.Thread(target=tcp_server)

    tcp_thread.daemon = True

    tcp_thread.start()

    udp_thread = threading.Thread(target=udp_server)

    udp_thread.daemon = True

    udp_thread.start()

    print(f"\n[HTTP] Puerto {HTTP_PORT}")

    app.run(

        host='0.0.0.0',

        port=HTTP_PORT,

        debug=False

    )
import socket
import threading
import time
import psutil
from flask import Flask, request, jsonify

try:
    from flask_cors import CORS
    FLASK_CORS = True
except ImportError:
    FLASK_CORS = False

TCP_HOST = "0.0.0.0"
TCP_PORT = 8080
UDP_HOST = "0.0.0.0"
UDP_PORT = 9090
HTTP_PORT = 5000

app = Flask(__name__)

if FLASK_CORS:
    CORS(app)

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        from flask import Response
        return Response(status=200)

# ─── State ────────────────────────────────────────────────
authorized_macs = ["94:e3:ee:45:d4:86"]
devices_detected = []
alerts_detected  = []

# Traffic history: list of {timestamp, bytes_sent, bytes_recv, mbps_out, mbps_in}
traffic_history  = []
_prev_net        = None
_prev_time       = None

# ─── Traffic Sampling ─────────────────────────────────────
def sample_traffic():
    """Corre en background, muestrea tráfico de red cada segundo."""
    global _prev_net, _prev_time, traffic_history
    while True:
        try:
            counters = psutil.net_io_counters()
            now = time.time()
            if _prev_net is not None:
                dt = now - _prev_time
                if dt > 0:
                    bytes_out = counters.bytes_sent - _prev_net.bytes_sent
                    bytes_in  = counters.bytes_recv - _prev_net.bytes_recv
                    mbps_out  = round((bytes_out * 8) / (dt * 1_000_000), 3)
                    mbps_in   = round((bytes_in  * 8) / (dt * 1_000_000), 3)
                    entry = {
                        "ts":        round(now),
                        "label":     time.strftime("%H:%M:%S", time.localtime(now)),
                        "mbps_out":  mbps_out,
                        "mbps_in":   mbps_in,
                        "bytes_sent_total": counters.bytes_sent,
                        "bytes_recv_total": counters.bytes_recv,
                    }
                    traffic_history.append(entry)
                    # Keep last 5 minutes (300 samples at 1/s)
                    if len(traffic_history) > 300:
                        traffic_history.pop(0)
            _prev_net  = counters
            _prev_time = now
        except Exception as e:
            print(f"[TRAFFIC ERROR] {e}")
        time.sleep(1)

# ─── Routes ───────────────────────────────────────────────

@app.route('/traffic', methods=['GET'])
def get_traffic():
    """
    Retorna el historial de tráfico de red en tiempo real.
    Query param: ?limit=60  (últimas N muestras, default 60)
    """
    limit = int(request.args.get('limit', 60))
    data = traffic_history[-limit:] if len(traffic_history) >= limit else traffic_history[:]
    
    # Totales acumulados desde inicio del proceso
    counters = psutil.net_io_counters()
    total_bytes = counters.bytes_sent + counters.bytes_recv
    total_tb    = round(total_bytes / 1e12, 3)
    total_gb    = round(total_bytes / 1e9,  2)
    
    # Ancho de banda actual (último sample)
    current_mbps_out = data[-1]['mbps_out'] if data else 0
    current_mbps_in  = data[-1]['mbps_in']  if data else 0
    current_mbps     = round(current_mbps_out + current_mbps_in, 2)

    return jsonify({
        "history":       data,
        "total_tb":      total_tb,
        "total_gb":      total_gb,
        "current_mbps":  current_mbps,
        "mbps_out":      current_mbps_out,
        "mbps_in":       current_mbps_in,
        "samples":       len(data),
    })

@app.route('/stats', methods=['GET'])
def get_stats():
    """Resumen general: tráfico, dispositivos, alertas."""
    counters = psutil.net_io_counters()
    total_bytes = counters.bytes_sent + counters.bytes_recv
    current = traffic_history[-1] if traffic_history else {}
    return jsonify({
        "devices_count": len(devices_detected),
        "alerts_count":  len(alerts_detected),
        "total_bytes":   total_bytes,
        "total_gb":      round(total_bytes / 1e9, 2),
        "total_tb":      round(total_bytes / 1e12, 3),
        "current_mbps":  current.get('mbps_out', 0) + current.get('mbps_in', 0),
        "mbps_out":      current.get('mbps_out', 0),
        "mbps_in":       current.get('mbps_in', 0),
    })

@app.route('/motion', methods=['POST'])
def motion():
    data = request.json
    print("\n[HTTP MOTION]", data)
    return jsonify({"status": "OK"})

@app.route('/device', methods=['POST'])
def receive_device():
    data      = request.get_json()
    mac_src   = data.get("mac_src")
    approved  = mac_src in authorized_macs
    device_info = {
        "timestamp": data.get("timestamp"),
        "event":     data.get("event"),
        "mac_src":   mac_src,
        "mac_dst":   data.get("mac_dst"),
        "approved":  approved,
    }
    devices_detected.append(device_info)
    print("\n[DEVICE]", device_info)
    return jsonify({"approved": approved})

@app.route('/alert', methods=['POST'])
def receive_alert():
    data  = request.get_json()
    event = data.get("event")
    alert_info = {
        "timestamp": data.get("timestamp"),
        "event":     event,
        "ip_src":    data.get("ip_src"),
    }
    if event == "DOS_ATTACK":
        alert_info["packets"]        = data.get("packets")
    elif event == "SYN_FLOOD":
        alert_info["syn_packets"]    = data.get("syn_packets")
    elif event == "PORT_SCAN":
        alert_info["ports_detected"] = data.get("ports_detected")

    alerts_detected.append(alert_info)
    print(f"\n[{event}]", alert_info)
    return jsonify({"status": "received", "event": event})

@app.route('/approve', methods=['POST'])
def approve_device():
    data = request.get_json()
    mac  = data.get("mac")
    if not mac:
        return jsonify({"status": "error", "message": "MAC requerida"}), 400
    if mac not in authorized_macs:
        authorized_macs.append(mac)
    # Actualizar el estado en devices_detected
    for d in devices_detected:
        if d.get("mac_src") == mac:
            d["approved"] = True
    print(f"\n[APPROVED] {mac}")
    return jsonify({"status": "approved", "mac": mac})

@app.route('/devices', methods=['GET'])
def get_devices():
    return jsonify(devices_detected)

@app.route('/alerts', methods=['GET'])
def get_alerts():
    return jsonify(alerts_detected)

@app.route('/authorized', methods=['GET'])
def get_authorized():
    return jsonify(authorized_macs)

# ─── TCP / UDP ─────────────────────────────────────────────
def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((TCP_HOST, TCP_PORT)); s.listen()
    print(f"[TCP] Puerto {TCP_PORT}")
    while True:
        client, addr = s.accept()
        print(f"[TCP] Conexión {addr}")
        data = client.recv(1024).decode()
        print(data)
        client.send(b"ACK\n"); client.close()

def udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((UDP_HOST, UDP_PORT))
    print(f"[UDP] Puerto {UDP_PORT}")
    while True:
        data, addr = s.recvfrom(1024)
        print(f"[UDP] {addr}: {data.decode()}")

if __name__ == '__main__':
    for target in [tcp_server, udp_server, sample_traffic]:
        t = threading.Thread(target=target)
        t.daemon = True; t.start()

    print(f"[HTTP] Puerto {HTTP_PORT}")
    print(f"[CORS] {'flask-cors' if FLASK_CORS else 'manual headers'}")
    app.run(host='0.0.0.0', port=HTTP_PORT, debug=False)

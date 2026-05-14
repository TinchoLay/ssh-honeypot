from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import json
import os
from collections import Counter
from datetime import datetime
from config import LOG_FILE, HTTP_LOG, FTP_LOG

app = Flask(__name__)
app.config["SECRET_KEY"] = "honeypot-dashboard-2026"
socketio = SocketIO(app, cors_allowed_origins="*")


# ─── CARGA DE DATOS ───────────────────────────────────────────────────────────

def load_json_log(filepath):
    records = []
    if not os.path.exists(filepath):
        return records
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records

def load_all_attempts():
    """Carga SSH + HTTP + FTP y los unifica con tipo."""
    ssh = load_json_log(LOG_FILE)
    for a in ssh:
        a["tipo"] = "SSH"

    http = load_json_log(HTTP_LOG)
    for a in http:
        a["tipo"] = "HTTP"
        # Normalizar campos para unificación
        if "username" not in a:
            a["username"] = a.get("username", "-")
        if "password" not in a:
            a["password"] = a.get("password", "-")
        if "country" not in a:
            a["country"] = "-"
        if "city" not in a:
            a["city"] = "-"
        if "lat" not in a:
            a["lat"] = None
        if "lon" not in a:
            a["lon"] = None

    ftp = load_json_log(FTP_LOG)
    for a in ftp:
        a["tipo"] = "FTP"
        if "country" not in a:
            a["country"] = "-"
        if "city" not in a:
            a["city"] = "-"
        if "lat" not in a:
            a["lat"] = None
        if "lon" not in a:
            a["lon"] = None

    all_attempts = ssh + http + ftp
    # Ordenar por timestamp
    all_attempts.sort(key=lambda x: x.get("timestamp", ""), reverse=False)
    return all_attempts


# ─── ESTADÍSTICAS ─────────────────────────────────────────────────────────────

def get_stats(attempts):
    if not attempts:
        return {
            "total": 0, "unique_ips": 0,
            "ssh_count": 0, "http_count": 0, "ftp_count": 0,
            "top_users": [], "top_passwords": [],
            "top_countries": [], "recent": [],
            "map_points": []
        }

    ips = set(a.get("ip") for a in attempts if a.get("ip"))

    ssh_attempts   = [a for a in attempts if a.get("tipo") == "SSH"]
    http_attempts  = [a for a in attempts if a.get("tipo") == "HTTP"]
    ftp_attempts   = [a for a in attempts if a.get("tipo") == "FTP"]

    # Solo SSH tiene credenciales completas para tops
    usernames  = Counter(a.get("username", "?") for a in ssh_attempts + ftp_attempts if a.get("username") not in [None, "-", ""])
    passwords  = Counter(a.get("password", "?") for a in ssh_attempts + ftp_attempts if a.get("password") not in [None, "-", ""])
    countries  = Counter(a.get("country", "?") for a in attempts if a.get("country") not in [None, "-", "Desconocido", "Local"])

    # Puntos para el mapa — agrupados por ciudad para evitar duplicados
    # por pequeñas diferencias de coordenadas en la misma ciudad
    coordenadas = {}
    for a in ssh_attempts:
        lat = a.get("lat")
        lon = a.get("lon")
        if lat is None or lon is None:
            continue
        country = a.get("country", "?")
        city = a.get("city", "?")
        key = (country, city)
        if key not in coordenadas:
            coordenadas[key] = {
                "lat": lat, "lon": lon, "count": 0,
                "country": country,
                "city": city,
                "ips": set()
            }
        coordenadas[key]["count"] += 1
        coordenadas[key]["ips"].add(a.get("ip", ""))

    map_points = [
        {
            "lat": v["lat"], "lon": v["lon"],
            "count": v["count"],
            "country": v["country"],
            "city": v["city"],
            "ips": len(v["ips"])
        }
        for v in coordenadas.values()
    ]

    recent = list(reversed(attempts[-20:]))

    return {
        "total":       len(attempts),
        "unique_ips":  len(ips),
        "ssh_count":   len(ssh_attempts),
        "http_count":  len(http_attempts),
        "ftp_count":   len(ftp_attempts),
        "top_users":     [{"name": k, "count": v} for k, v in usernames.most_common(5)],
        "top_passwords": [{"name": k, "count": v} for k, v in passwords.most_common(5)],
        "top_countries": [{"name": k, "count": v} for k, v in countries.most_common(5)],
        "recent":      recent,
        "map_points":  map_points
    }


# ─── ANÁLISIS TEMPORAL ────────────────────────────────────────────────────────

def get_analisis_data(attempts):
    if not attempts:
        return {}

    por_hora = [0] * 24
    for a in attempts:
        try:
            hora = int(a["timestamp"].split(" ")[1].split(":")[0])
            por_hora[hora] += 1
        except Exception:
            pass

    dias_labels = ["Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado", "Domingo"]
    por_dia = [0] * 7
    for a in attempts:
        try:
            dt = datetime.strptime(a["timestamp"], "%Y-%m-%d %H:%M:%S")
            por_dia[dt.weekday()] += 1
        except Exception:
            pass

    paises = Counter(
        a.get("country", "?") for a in attempts
        if a.get("country") not in ["Local", "Desconocido", None, "-"]
    )

    fechas = Counter(a["timestamp"].split(" ")[0] for a in attempts if a.get("timestamp"))
    fechas_ordenadas = dict(sorted(fechas.items()))

    # Por tipo por hora
    ssh_por_hora   = [0] * 24
    http_por_hora  = [0] * 24
    ftp_por_hora   = [0] * 24
    for a in attempts:
        try:
            hora = int(a["timestamp"].split(" ")[1].split(":")[0])
            t = a.get("tipo", "SSH")
            if t == "SSH":   ssh_por_hora[hora]  += 1
            elif t == "HTTP": http_por_hora[hora] += 1
            elif t == "FTP":  ftp_por_hora[hora]  += 1
        except Exception:
            pass

    return {
        "por_hora":      por_hora,
        "por_dia":       por_dia,
        "dias_labels":   dias_labels,
        "top_paises":    dict(paises.most_common(10)),
        "timeline":      fechas_ordenadas,
        "total":         len(attempts),
        "ssh_por_hora":  ssh_por_hora,
        "http_por_hora": http_por_hora,
        "ftp_por_hora":  ftp_por_hora,
    }


# ─── RUTAS ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    attempts = load_all_attempts()
    stats = get_stats(attempts)
    return render_template("index.html", stats=stats)

@app.route("/analisis")
def analisis():
    attempts = load_all_attempts()
    datos = get_analisis_data(attempts)
    return render_template("analisis.html", datos=datos)

@app.route("/api/stats")
def api_stats():
    """Endpoint JSON para auto-refresh del dashboard."""
    attempts = load_all_attempts()
    stats = get_stats(attempts)
    return jsonify(stats)

@app.route("/api/analisis")
def api_analisis():
    """Endpoint JSON para auto-refresh del análisis."""
    attempts = load_all_attempts()
    datos = get_analisis_data(attempts)
    return jsonify(datos)

@app.route("/mapa")
def mapa():
    """Página del mapa de calor embebido."""
    attempts = load_all_attempts()
    stats = get_stats(attempts)
    map_points_json = json.dumps(stats["map_points"])
    return render_template("mapa.html", map_points=map_points_json)


# ─── WEBSOCKETS ───────────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    attempts = load_all_attempts()
    stats = get_stats(attempts)
    socketio.emit("update", stats)

def notify_new_attempt(attempt):
    """Llamar desde logger.py, http_honeypot.py y ftp_honeypot.py."""
    attempts = load_all_attempts()
    stats = get_stats(attempts)
    socketio.emit("update", stats)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("🖥️  Dashboard activo en http://localhost:5000")
    print("   Rutas disponibles:")
    print("   /          → Dashboard principal")
    print("   /analisis  → Análisis temporal")
    print("   /mapa      → Mapa de calor mundial")
    print("   /api/stats → JSON con stats actuales")
    socketio.run(app, debug=False, host="0.0.0.0", port=5000)

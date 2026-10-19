from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import json
import os
import threading
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
    for a in attempts:
        lat = a.get("lat")
        lon = a.get("lon")
        if lat is None or lon is None:
            continue
        tipo = a.get("tipo", "SSH")
        country = a.get("country", "?")
        city = a.get("city", "?")
        key = (country, city)
        if key not in coordenadas:
            coordenadas[key] = {
                "lat": lat, "lon": lon,
                "country": country, "city": city,
                "por_tipo": {}
            }
        t = coordenadas[key]["por_tipo"].setdefault(tipo, {"count": 0, "ips": set()})
        t["count"] += 1
        t["ips"].add(a.get("ip", ""))

    map_points = [
        {
            "lat": v["lat"], "lon": v["lon"],
            "country": v["country"], "city": v["city"],
            # totales (los usa tambien la pagina vieja /mapa)
            "count": sum(d["count"] for d in v["por_tipo"].values()),
            "ips": len(set().union(*(d["ips"] for d in v["por_tipo"].values()))),
            # {"SSH": {"count": n, "ips": m}, "HTTP": {...}} para filtrar en el front
            "por_tipo": {t: {"count": d["count"], "ips": len(d["ips"])}
                         for t, d in v["por_tipo"].items()}
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


# ─── DATOS DEL MAPA (con filtros en el navegador) ─────────────────────────────

TIPOS_MAPA = ["SSH", "HTTP", "FTP"]
EDAD_DESCONOCIDA = 10**10   # eventos con timestamp ilegible: solo entran en "desde el inicio"

def get_map_data(attempts):
    """Datos compactos para filtrar el mapa en el navegador por tipo y por periodo.

    Cada evento es [indice_ubicacion, indice_tipo, edad_en_segundos, indice_ip]. Se manda la
    edad ya calculada (ahora - timestamp con el mismo reloj del contenedor), asi no importa en
    que zona horaria estan los logs. Las IPs viajan como indices: sirven para contar IPs unicas
    sin exponer la lista."""
    ahora = datetime.now()
    indice_loc, locs = {}, []
    indice_ip, eventos = {}, []

    for a in attempts:
        lat, lon = a.get("lat"), a.get("lon")
        tipo = a.get("tipo")
        if lat is None or lon is None or tipo not in TIPOS_MAPA:
            continue
        clave = (a.get("country", "?"), a.get("city", "?"))
        if clave not in indice_loc:
            indice_loc[clave] = len(locs)
            locs.append({"lat": lat, "lon": lon, "country": clave[0], "city": clave[1]})
        ip = a.get("ip", "")
        if ip not in indice_ip:
            indice_ip[ip] = len(indice_ip)
        try:
            edad = int((ahora - datetime.strptime(a.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")).total_seconds())
            edad = max(edad, 0)
        except (ValueError, TypeError):
            edad = EDAD_DESCONOCIDA
        eventos.append([indice_loc[clave], TIPOS_MAPA.index(tipo), edad, indice_ip[ip]])

    return {"locs": locs, "events": eventos}


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

@app.route("/api/mapa")
def api_mapa():
    """Eventos compactos para el mapa con filtros (se pide solo al abrir la pestana Mapa)."""
    return jsonify(get_map_data(load_all_attempts()))

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

_notify_lock = threading.Lock()
_notify_pendiente = False

def _emitir_update():
    global _notify_pendiente
    with _notify_lock:
        _notify_pendiente = False
    attempts = load_all_attempts()
    stats = get_stats(attempts)
    socketio.emit("update", stats)

def notify_new_attempt(attempt):
    """Llamar desde logger.py, http_honeypot.py y ftp_honeypot.py.

    Cada aviso releia todos los logs y reenviaba todo. Con el puerto 22 abierto llegan
    muchos eventos por segundo y eso crece de forma cuadratica, asi que se agrupan: como
    mucho una actualizacion cada ~1.5 segundos, que siempre refleja el ultimo estado."""
    global _notify_pendiente
    with _notify_lock:
        if _notify_pendiente:
            return
        _notify_pendiente = True
    threading.Timer(1.5, _emitir_update).start()


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("🖥️  Dashboard activo en http://localhost:5000")
    print("   Rutas disponibles:")
    print("   /          → Dashboard principal")
    print("   /analisis  → Análisis temporal")
    print("   /mapa      → Mapa de calor mundial")
    print("   /api/stats → JSON con stats actuales")
    socketio.run(app, debug=False, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)

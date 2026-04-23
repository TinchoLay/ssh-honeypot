from flask import Flask, render_template
from flask_socketio import SocketIO
import json
import os
from config import LOG_FILE

app = Flask(__name__)
app.config["SECRET_KEY"] = "honeypot-dashboard-2026"
socketio = SocketIO(app, cors_allowed_origins="*")

def load_attempts():
    """Carga todos los intentos del archivo JSON."""
    attempts = []
    if not os.path.exists(LOG_FILE):
        return attempts
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    attempts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return attempts

def get_stats(attempts):
    """Genera las estadísticas para el dashboard."""
    from collections import Counter
    
    if not attempts:
        return {
            "total": 0,
            "unique_ips": 0,
            "top_users": [],
            "top_passwords": [],
            "top_countries": [],
            "recent": []
        }
    
    usernames  = Counter(a.get("username", "?") for a in attempts)
    passwords  = Counter(a.get("password", "?") for a in attempts)
    countries  = Counter(a.get("country", "?") for a in attempts)
    ips        = set(a.get("ip") for a in attempts)
    
    return {
        "total": len(attempts),
        "unique_ips": len(ips),
        "top_users":     [{"name": k, "count": v} for k, v in usernames.most_common(5)],
        "top_passwords": [{"name": k, "count": v} for k, v in passwords.most_common(5)],
        "top_countries": [{"name": k, "count": v} for k, v in countries.most_common(5)],
        "recent": list(reversed(attempts[-10:]))  # últimos 10 ataques
    }

@app.route("/")
def index():
    """Página principal del dashboard."""
    attempts = load_attempts()
    stats = get_stats(attempts)
    return render_template("index.html", stats=stats)

@socketio.on("connect")
def on_connect():
    """Cuando un navegador se conecta, le manda las stats actuales."""
    attempts = load_attempts()
    stats = get_stats(attempts)
    socketio.emit("update", stats)

def notify_new_attempt(attempt):
    """Llamá esta función cada vez que llega un ataque nuevo."""
    attempts = load_attempts()
    stats = get_stats(attempts)
    socketio.emit("update", stats)

if __name__ == "__main__":
    print("🖥️  Dashboard activo en http://localhost:5000")
    print("   Abrí esa URL en tu navegador")
    socketio.run(app, debug=False, host="0.0.0.0", port=5000)
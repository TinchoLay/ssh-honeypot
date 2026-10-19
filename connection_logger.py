"""Registro de conexiones SSH, con o sin login.

Un scanner que se conecta, lee el banner y se va nunca llega a probar una clave, asi que
save_attempt() no lo ve. Aca queda un evento por conexion, con el resultado, para poder
contar cuantos solo miran y cuantos prueban credenciales.

Va a su propio archivo (logs/ssh_connections.json) y no a attempts.json: son cosas distintas
y el dashboard, el clasificador ML y las estadisticas no tienen que mezclarlas.
"""
import json
import os
import threading
from datetime import datetime
from config import es_ip_propia

CONNECTIONS_LOG = os.path.join("logs", "ssh_connections.json")
_lock = threading.Lock()


def save_connection(ip, resultado, banner=None, duracion=None, intentos=0, detalle=None):
    """Guarda un evento ssh_connection. Ignora las IPs propias, como el resto de los colectores."""
    if es_ip_propia(ip):
        return
    evento = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "honeypot_event": "ssh_connection",
        "ip": ip,
        "resultado": resultado,
        "banner": (banner or "")[:200],
        "duracion_seg": round(duracion, 1) if duracion is not None else None,
        "intentos_login": intentos,
    }
    if detalle:
        evento["detalle"] = str(detalle)[:120]
    try:
        os.makedirs("logs", exist_ok=True)
        with _lock:
            with open(CONNECTIONS_LOG, "a", encoding="utf-8") as f:
                json.dump(evento, f)
                f.write("\n")
    except OSError:
        # Un problema de disco no debe tumbar la conexion
        pass

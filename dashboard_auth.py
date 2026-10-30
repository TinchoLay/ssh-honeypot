"""Autenticacion del dashboard: una clave compartida, sesion por cookie, y el websocket incluido.

El dashboard solo escucha en 127.0.0.1 del host (docker-compose.yml) y se usa por tunel SSH, asi
que esto es una segunda capa: si alguien llega al puerto (un tunel compartido, otro usuario del
servidor, una pagina web maliciosa que apunte a localhost:5000), todavia necesita la clave.

Como funciona:
- La clave sale de la variable de entorno DASHBOARD_PASSWORD (en el .env del servidor, fuera de git).
- Sin clave configurada el dashboard queda BLOQUEADO (503), no abierto. Para desarrollo local se
  puede desactivar a proposito con DASHBOARD_AUTH=off.
- Se entra por /login; la sesion vive en una cookie firmada, HttpOnly y SameSite=Strict.
- El websocket (Socket.IO) tambien se autentica: el handler de "connect" rechaza si la sesion no
  tiene login. Es necesario porque Socket.IO atiende /socket.io/ antes que Flask, asi que
  before_request no lo cubre.
- Despues de 5 claves incorrectas en 5 minutos se bloquean los intentos durante un minuto.

Limites conocidos, a proposito: una sola clave compartida, sin segundo factor, y el limite de
intentos es global (no por IP: detras del tunel todos llegan como la misma direccion). Un cliente
sin login puede abrir una sesion de Engine.IO, pero el servidor rechaza el namespace y no le envia
datos.
"""
import hmac
import os
import threading
import time

from flask import Response, redirect, request, session

MAX_FALLOS = 5
VENTANA_SEG = 300
BLOQUEO_SEG = 60

_lock = threading.Lock()
_fallos = []
_bloqueado_hasta = 0.0

_PAGINA = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Honeypot dashboard</title>
<style>body{{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0}}
form{{background:#161b22;padding:2rem;border-radius:8px;min-width:260px}}input,button{{width:100%;padding:.6rem;margin-top:.8rem;box-sizing:border-box;font-size:1rem}}
p{{color:#f85149;margin:.8rem 0 0}}</style></head><body>
<form method="post" action="/login"><strong>Dashboard</strong>
<input type="password" name="password" placeholder="Clave" autofocus autocomplete="current-password">
<button type="submit">Entrar</button>{error}</form></body></html>"""


def modo():
    """'off' (desarrollo local, explicito), 'on' (hay clave) o 'bloqueado' (falta la clave)."""
    if os.getenv("DASHBOARD_AUTH", "").strip().lower() == "off":
        return "off"
    return "on" if os.getenv("DASHBOARD_PASSWORD") else "bloqueado"


def _clave_correcta(ingresada):
    esperada = os.getenv("DASHBOARD_PASSWORD", "")
    return bool(esperada) and hmac.compare_digest(ingresada.encode(), esperada.encode())


def _esta_bloqueado(ahora):
    return ahora < _bloqueado_hasta


def _registrar_fallo(ahora):
    global _bloqueado_hasta
    with _lock:
        _fallos[:] = [t for t in _fallos if ahora - t < VENTANA_SEG] + [ahora]
        if len(_fallos) >= MAX_FALLOS:
            _bloqueado_hasta = ahora + BLOQUEO_SEG
            _fallos.clear()


def reiniciar_limite():
    """Solo para los tests."""
    global _bloqueado_hasta
    with _lock:
        _fallos.clear()
        _bloqueado_hasta = 0.0


def socket_autorizado():
    """Lo usa el handler de connect del websocket."""
    m = modo()
    return m == "off" or (m == "on" and bool(session.get("ok")))


def registrar(app):
    """Conecta la autenticacion a la app de Flask."""

    @app.before_request
    def exigir_login():
        if request.path == "/login":
            return None
        m = modo()
        if m == "off" or (m == "on" and session.get("ok")):
            return None
        if m == "bloqueado":
            return Response("Dashboard bloqueado: falta DASHBOARD_PASSWORD en el entorno del contenedor.\n",
                            status=503, mimetype="text/plain")
        if request.path.startswith("/api/") or request.path.startswith("/socket.io/"):
            return Response("No autorizado\n", status=401, mimetype="text/plain")
        return redirect("/login")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        m = modo()
        if m == "bloqueado":
            return Response("Dashboard bloqueado: falta DASHBOARD_PASSWORD en el entorno del contenedor.\n",
                            status=503, mimetype="text/plain")
        if m == "off":
            return redirect("/")
        if request.method == "POST":
            ahora = time.time()
            if _esta_bloqueado(ahora):
                return Response(_PAGINA.format(error="<p>Demasiados intentos. Espera un minuto.</p>"), status=429)
            if _clave_correcta(request.form.get("password", "")):
                session.clear()
                session["ok"] = True
                session.permanent = True
                return redirect("/")
            _registrar_fallo(ahora)
            return Response(_PAGINA.format(error="<p>Clave incorrecta.</p>"), status=401)
        return Response(_PAGINA.format(error=""))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect("/login")

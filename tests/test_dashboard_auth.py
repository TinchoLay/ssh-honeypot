"""Tests de la autenticacion del dashboard (HTTP y websocket). No usan red ni tocan los logs reales."""
import json

import pytest

import dashboard
import dashboard_auth

CLAVE = "clave-de-prueba-123"


@pytest.fixture(autouse=True)
def entorno_limpio(monkeypatch, tmp_path):
    """Cada test arranca sin clave configurada, sin bloqueos y en una carpeta vacia (sin logs)."""
    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    monkeypatch.delenv("DASHBOARD_AUTH", raising=False)
    monkeypatch.chdir(tmp_path)
    dashboard_auth.reiniciar_limite()
    yield
    dashboard_auth.reiniciar_limite()


@pytest.fixture(autouse=True)
def restaurar_servidor_socketio():
    """El cliente de pruebas de Flask-SocketIO reemplaza _send_packet y _send_eio_packet del servidor
    y no los devuelve. Sin esto, los tests del handshake real que corren despues se cuelgan 25 s."""
    servidor = dashboard.socketio.server
    guardados = {n: servidor.__dict__.get(n) for n in ("_send_packet", "_send_eio_packet")}
    yield
    for nombre, valor in guardados.items():
        if valor is None:
            servidor.__dict__.pop(nombre, None)
        else:
            servidor.__dict__[nombre] = valor


@pytest.fixture
def con_clave(monkeypatch):
    monkeypatch.setenv("DASHBOARD_PASSWORD", CLAVE)


@pytest.fixture
def cliente():
    return dashboard.app.test_client()


def _entrar(cliente, clave=CLAVE):
    return cliente.post("/login", data={"password": clave})


RUTAS_PAGINA = ["/", "/analisis", "/mapa"]
RUTAS_API = ["/api/stats", "/api/mapa", "/api/analisis"]


# --- Modos ------------------------------------------------------------------------

def test_modo(monkeypatch):
    assert dashboard_auth.modo() == "bloqueado"
    monkeypatch.setenv("DASHBOARD_PASSWORD", CLAVE)
    assert dashboard_auth.modo() == "on"
    monkeypatch.setenv("DASHBOARD_AUTH", "OFF")
    assert dashboard_auth.modo() == "off"


@pytest.mark.parametrize("ruta", RUTAS_PAGINA + RUTAS_API + ["/login"])
def test_sin_clave_configurada_todo_queda_bloqueado(cliente, ruta):
    assert cliente.get(ruta).status_code == 503


def test_con_auth_off_el_dashboard_queda_abierto(cliente, monkeypatch):
    monkeypatch.setenv("DASHBOARD_AUTH", "off")
    assert cliente.get("/api/stats").status_code == 200
    assert cliente.get("/login").status_code == 302


# --- HTTP -------------------------------------------------------------------------

@pytest.mark.usefixtures("con_clave")
@pytest.mark.parametrize("ruta", RUTAS_PAGINA)
def test_las_paginas_redirigen_al_login(cliente, ruta):
    r = cliente.get(ruta)
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


@pytest.mark.usefixtures("con_clave")
@pytest.mark.parametrize("ruta", RUTAS_API)
def test_la_api_responde_401_sin_login(cliente, ruta):
    r = cliente.get(ruta)
    assert r.status_code == 401
    assert b"{" not in r.data          # ningun dato en la respuesta


@pytest.mark.usefixtures("con_clave")
def test_clave_incorrecta_no_da_sesion(cliente):
    r = _entrar(cliente, "otra")
    assert r.status_code == 401
    assert cliente.get("/api/stats").status_code == 401


@pytest.mark.usefixtures("con_clave")
def test_clave_vacia_no_entra(cliente):
    assert _entrar(cliente, "").status_code == 401


@pytest.mark.usefixtures("con_clave")
def test_login_correcto_da_acceso_a_todo(cliente):
    r = _entrar(cliente)
    assert r.status_code == 302
    for ruta in RUTAS_PAGINA + RUTAS_API:
        assert cliente.get(ruta).status_code == 200, ruta


@pytest.mark.usefixtures("con_clave")
def test_logout_cierra_la_sesion(cliente):
    _entrar(cliente)
    cliente.get("/logout")
    assert cliente.get("/api/stats").status_code == 401


@pytest.mark.usefixtures("con_clave")
def test_la_cookie_es_httponly_y_samesite_strict(cliente):
    cookie = _entrar(cliente).headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


@pytest.mark.usefixtures("con_clave")
def test_bloqueo_tras_cinco_fallos_y_se_levanta_con_el_tiempo(cliente, monkeypatch):
    reloj = [1000.0]
    monkeypatch.setattr(dashboard_auth.time, "time", lambda: reloj[0])
    for _ in range(5):
        assert _entrar(cliente, "mal").status_code == 401
    assert _entrar(cliente).status_code == 429          # ni la clave correcta entra mientras dura
    reloj[0] += dashboard_auth.BLOQUEO_SEG + 1
    assert _entrar(cliente).status_code == 302


@pytest.mark.usefixtures("con_clave")
def test_los_fallos_viejos_no_cuentan(cliente, monkeypatch):
    reloj = [1000.0]
    monkeypatch.setattr(dashboard_auth.time, "time", lambda: reloj[0])
    for _ in range(4):
        _entrar(cliente, "mal")
    reloj[0] += dashboard_auth.VENTANA_SEG + 1
    _entrar(cliente, "mal")                              # el 5.o, pero los otros ya vencieron
    assert _entrar(cliente).status_code == 302


# --- Websocket --------------------------------------------------------------------

@pytest.mark.usefixtures("con_clave")
def test_el_websocket_rechaza_sin_login(cliente):
    ws = dashboard.socketio.test_client(dashboard.app, flask_test_client=cliente)
    assert not ws.is_connected()


@pytest.mark.usefixtures("con_clave")
def test_el_websocket_acepta_con_login_y_manda_datos(cliente):
    _entrar(cliente)
    ws = dashboard.socketio.test_client(dashboard.app, flask_test_client=cliente)
    assert ws.is_connected()
    recibidos = ws.get_received()
    assert any(m["name"] == "update" for m in recibidos)
    ws.disconnect()


@pytest.mark.usefixtures("con_clave")
def test_el_websocket_rechaza_despues_del_logout(cliente):
    _entrar(cliente)
    cliente.get("/logout")
    ws = dashboard.socketio.test_client(dashboard.app, flask_test_client=cliente)
    assert not ws.is_connected()


def test_sin_clave_el_websocket_tambien_queda_cerrado(cliente):
    ws = dashboard.socketio.test_client(dashboard.app, flask_test_client=cliente)
    assert not ws.is_connected()


def test_un_login_ajeno_no_abre_el_websocket_de_otro_cliente(monkeypatch):
    monkeypatch.setenv("DASHBOARD_PASSWORD", CLAVE)
    a, b = dashboard.app.test_client(), dashboard.app.test_client()
    _entrar(a)
    assert dashboard.socketio.test_client(dashboard.app, flask_test_client=a).is_connected()
    assert not dashboard.socketio.test_client(dashboard.app, flask_test_client=b).is_connected()


# --- Configuracion ----------------------------------------------------------------

def test_no_queda_la_clave_de_cookies_fija_del_codigo():
    assert dashboard.app.config["SECRET_KEY"] != "honeypot-dashboard-2026"
    assert len(dashboard.app.config["SECRET_KEY"]) >= 32


def test_el_websocket_no_acepta_cualquier_origen():
    # cors_allowed_origins="*" dejaria que una pagina de otro sitio abra el websocket con tus cookies
    assert dashboard.socketio.server.eio.cors_allowed_origins != "*"


# --- Handshake real de Socket.IO por HTTP (sin el atajo del cliente de pruebas) ---------
# Socket.IO atiende /socket.io/ antes que Flask: before_request no lo ve, por eso la validacion
# esta en el handler de connect. Estas pruebas recorren el protocolo de verdad: abrir sesion de
# Engine.IO, pedir el namespace y ver que contesta el servidor.

def _handshake_polling(cliente):
    abrir = cliente.get("/socket.io/?EIO=4&transport=polling").get_data(as_text=True)
    sid = json.loads(abrir[1:])["sid"]
    url = f"/socket.io/?EIO=4&transport=polling&sid={sid}"
    cliente.post(url, data="40", content_type="text/plain;charset=UTF-8")   # pedir conectarse al namespace
    return cliente.get(url).get_data(as_text=True)


@pytest.mark.usefixtures("con_clave")
def test_handshake_http_sin_login_recibe_error_y_ningun_dato(cliente):
    cuerpo = _handshake_polling(cliente)
    assert cuerpo.startswith("44")                     # CONNECT_ERROR del protocolo Socket.IO
    assert "update" not in cuerpo and "attempts" not in cuerpo


@pytest.mark.usefixtures("con_clave")
def test_handshake_http_con_login_recibe_conexion_y_update(cliente):
    _entrar(cliente)
    cuerpo = _handshake_polling(cliente)
    assert '40{"sid"' in cuerpo                        # CONNECT aceptado
    assert '"update"' in cuerpo and "44" not in cuerpo.split("\x1e")[0][:2]


def test_handshake_http_sin_clave_configurada_tambien_rechaza(cliente):
    assert _handshake_polling(cliente).startswith("44")

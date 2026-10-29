"""Preparacion comun de los tests de la shell falsa.

fake_shell.py importa shell_logger y logger (arrastran scikit-learn y requests, y escriben en logs/) y,
al detectar una descarga, malware_capture (que sale a internet). Los tests no deben
hacer ninguna de las dos cosas, asi que se reemplazan por dobles antes de importar
fake_shell. El resultado: los tests solo necesitan paramiko y pytest, corren en
milisegundos y no tocan disco ni red.
"""
import sys
import types

import pytest

# Cada llamada a save_command queda aca: (ip, comando, nota, canal)
REGISTRO = []
DESCARGAS = []


def _save_command(ip, command, nota="", canal="shell"):
    REGISTRO.append((ip, command, nota, canal))


def _capturar_en_background(url, ip):
    DESCARGAS.append((url, ip))


_logger = types.ModuleType("shell_logger")
_logger.save_command = _save_command
sys.modules["shell_logger"] = _logger

ATTEMPTS = []


def _save_attempt(ip, username, password):
    ATTEMPTS.append((ip, username, password))


_login = types.ModuleType("logger")
_login.save_attempt = _save_attempt
sys.modules["logger"] = _login

_malware = types.ModuleType("malware_capture")
_malware.capturar_en_background = _capturar_en_background
sys.modules["malware_capture"] = _malware

import fake_shell  # noqa: E402  (tiene que importarse despues de los dobles)


@pytest.fixture(autouse=True)
def limpiar_estado():
    """Estado limpio en cada test: sin registros previos ni intentos de login acumulados."""
    REGISTRO.clear()
    DESCARGAS.clear()
    ATTEMPTS.clear()
    fake_shell._fallos.clear()
    yield


@pytest.fixture
def registro():
    return REGISTRO


@pytest.fixture
def intentos():
    return ATTEMPTS


@pytest.fixture
def descargas():
    return DESCARGAS


@pytest.fixture
def shell():
    """Ejecuta un comando como lo haria un atacante recien autenticado.

    Devuelve (respuesta, estado). Si se pasa `estado`, se reutiliza para encadenar
    comandos de una misma sesion (cd y despues pwd, por ejemplo).
    """
    def _ejecutar(comando, usuario="root", estado=None, ip="203.0.113.7"):
        if estado is None:
            estado = {"cwd": fake_shell._home(usuario)}
        respuesta = fake_shell.get_response(comando, ip, usuario, estado)
        return respuesta, estado
    return _ejecutar

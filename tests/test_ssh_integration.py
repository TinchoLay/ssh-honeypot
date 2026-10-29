"""Prueba de punta a punta del servidor SSH falso, sin red real.

Se levanta el servidor con el mismo armado que honeypot.py (paramiko.Transport +
FakeShell + manejar_exec/manejar_shell) sobre un par de sockets en memoria, y un
cliente paramiko real se conecta. Sirve sobre todo para una cosa: que subir la
version de paramiko no rompa la negociacion, la autenticacion ni el canal exec.
"""
import socket
import threading

import paramiko
import pytest

import fake_shell

IP = "203.0.113.50"
CLAVE_DEBIL = next(iter(fake_shell.CLAVES_DEBILES))


def _servidor(sock, host_key, ip=IP):
    """Mismo flujo que handle_connection() de honeypot.py, reducido a lo esencial.
    Igual que el honeypot real, ignora los cortes de conexion: un cliente que se va
    mientras el servidor todavia escribe es lo normal en internet."""
    server = fake_shell.FakeShell(ip)
    transport = paramiko.Transport(sock)
    try:
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        transport.add_server_key(host_key)
        transport.start_server(server=server)
        canal = transport.accept(10)
        if canal is None:
            return
        server.event.wait(10)
        if server.exec_command is not None:
            fake_shell.manejar_exec(canal, ip, server.username, server.exec_command)
        else:
            fake_shell.manejar_shell(canal, ip, server.username)
    except (EOFError, OSError, paramiko.SSHException):
        pass


@pytest.fixture(scope="module")
def host_key():
    return paramiko.RSAKey.generate(2048)


@pytest.fixture
def conexion(host_key):
    """Devuelve una funcion que abre un cliente conectado al servidor falso."""
    abiertos = []

    def _abrir():
        s_srv, s_cli = socket.socketpair()
        hilo = threading.Thread(target=_servidor, args=(s_srv, host_key), daemon=True)
        hilo.start()
        cliente = paramiko.Transport(s_cli)
        abiertos.append(cliente)
        cliente.start_client(timeout=10)
        return cliente

    yield _abrir
    for c in abiertos:
        c.close()


def _exec(cliente, comando):
    canal = cliente.open_session()
    canal.exec_command(comando)
    salida = b""
    while True:
        datos = canal.recv(4096)
        if not datos:
            break
        salida += datos
    return salida.decode(), canal.recv_exit_status()


def test_negociacion_y_exec_con_clave_debil(conexion, intentos):
    cliente = conexion()
    cliente.auth_password("root", CLAVE_DEBIL)
    assert cliente.is_authenticated()
    salida, codigo = _exec(cliente, "uname -s -v -n -r -m")
    assert salida == "Linux ubuntu-server 5.15.0-1034-aws #38-Ubuntu SMP Mon Mar 20 15:41:27 UTC 2023 x86_64\n"
    assert codigo == 0
    assert intentos == [(IP, "root", CLAVE_DEBIL)]


def test_clave_fuerte_se_rechaza_al_primer_intento(conexion, intentos):
    cliente = conexion()
    with pytest.raises(paramiko.AuthenticationException):
        cliente.auth_password("root", "una-clave-fuerte-que-no-esta-en-la-lista-7Q")
    assert not cliente.is_authenticated()
    assert len(intentos) == 1      # el intento rechazado igual queda registrado


def test_tercer_intento_entra(conexion):
    cliente = conexion()
    clave = "una-clave-fuerte-que-no-esta-en-la-lista-7Q"
    for _ in range(2):
        with pytest.raises(paramiko.AuthenticationException):
            cliente.auth_password("admin", clave)
    cliente.auth_password("admin", clave)
    assert cliente.is_authenticated()


def test_exec_con_codigo_de_error(conexion):
    cliente = conexion()
    cliente.auth_password("root", CLAVE_DEBIL)
    salida, codigo = _exec(cliente, "foobar")
    assert salida == "bash: foobar: command not found\n"
    assert codigo == 127


def test_shell_interactiva_muestra_prompt_y_responde(conexion):
    cliente = conexion()
    cliente.auth_password("root", CLAVE_DEBIL)
    canal = cliente.open_session()
    canal.get_pty()
    canal.invoke_shell()
    canal.settimeout(10)
    leido = b""
    while b"root@ubuntu-server:~# " not in leido:
        leido += canal.recv(4096)
    canal.send(b"whoami\r")
    leido = b""
    while leido.count(b"root@ubuntu-server:~# ") < 1 or b"root\r\n" not in leido:
        leido += canal.recv(4096)
    assert b"root\r\n" in leido
    canal.send(b"exit\r")


def test_examen_de_shell_completo_por_ssh_real(conexion):
    """El examen que hacen los bots (ver test_fake_shell.py), pero por un cliente SSH real:
    cada comando por su propia conexion y su propio canal exec, como lo mandan ellos."""
    import re
    from pathlib import Path
    h = "b39c2c71df8f9ed54cbdac351074a6aa"
    comandos = [l.replace("HASH", h) for l in
                (Path(__file__).parent / "fixtures" / "examen_shell.txt").read_text(encoding="utf-8").splitlines()
                if l.strip()]
    salidas = []
    for comando in comandos:
        # una conexion por comando: el servidor atiende un exec y cierra, y los bots reconectan
        cliente = conexion()
        cliente.auth_password("root", CLAVE_DEBIL)
        salida, codigo = _exec(cliente, comando)
        assert codigo == 0
        salidas.append(salida)
    assert salidas[1] == f"\ncheck_{h}_small_math|56766\n"
    assert re.fullmatch(rf"\ncheck_{h}_small_pid\|\d+\n", salidas[2])
    assert salidas[3] == f"\ncheck_{h}_small_positional|2|check_{h}_arg1|check_{h}_arg2\n"
    assert salidas[4] == f"\ncheck_{h}_small_function|check_{h}_function_value|1\n"
    assert salidas[6] == f"\ncheck_{h}_transport_done\n"

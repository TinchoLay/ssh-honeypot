import logging
import os
import socket
import threading
import time
import paramiko
from logger import save_attempt
from connection_logger import save_connection
from config import HOST, PORT, BANNER, MAX_CONNECTIONS
from stats import show_stats
from fake_shell import FakeShell, manejar_shell, manejar_exec

# Un scanner que corta la conexion antes del banner hace que paramiko imprima un traceback
# entero. Esos errores ya quedan registrados como evento en ssh_connections.json, asi que se
# silencia el logger para no llenar el log del contenedor. Tambien oculta otros errores del
# transporte: si hay que depurar paramiko, comentar esta linea.
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

HOST_KEY_PATH = os.path.join("logs", "ssh_host_rsa_key")

def cargar_host_key():
    """Usa siempre la misma clave de host entre reinicios: un servidor real no la cambia
    y los clientes que ya se conectaron lo notarian. Se guarda en logs/ (volumen),
    asi sobrevive a los rebuilds del contenedor. logs/ esta en .gitignore."""
    os.makedirs("logs", exist_ok=True)
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    try:
        os.chmod(HOST_KEY_PATH, 0o600)
    except OSError:
        pass
    return key

host_key = cargar_host_key()

def handle_connection(client_ip, client_socket):
    inicio = time.time()
    server = FakeShell(client_ip)
    transport = None
    etapa = "negociacion"
    resultado = "sin_autenticacion"
    detalle = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = BANNER
        transport.add_server_key(host_key)

        transport.start_server(server=server)
        etapa = "sesion"

        try:
            from fingerprint import registrar_banner
            remote_version = transport.remote_version
            if remote_version:
                registrar_banner(client_ip, remote_version)
        except Exception:
            pass

        channel = transport.accept(20)
        if channel is None:
            if server.autenticado:
                resultado = "autenticado_sin_shell"
            elif server.intentos:
                resultado = "login_fallido"
            return

        server.event.wait(10)
        if not server.event.is_set():
            resultado = "autenticado_sin_shell"
            return

        username = getattr(server, "username", "unknown")
        if server.exec_command is not None:
            # Comando directo (ssh host "cmd"): es lo que hacen la mayoria de los bots
            resultado = "exec"
            detalle = server.exec_command
            manejar_exec(channel, client_ip, username, server.exec_command)
        else:
            resultado = "shell"
            manejar_shell(channel, client_ip, username)

    except Exception as e:
        if etapa == "negociacion":
            # La conexion murio antes de terminar el saludo SSH. Si el cliente nunca mando
            # un banner SSH valido (corto sin hablar, o mando otra cosa), es "sin_banner"
            recibio_banner = bool(getattr(transport, "remote_version", ""))
            resultado = "error_protocolo" if recibio_banner else "sin_banner"
            detalle = str(e) or type(e).__name__
    finally:
        banner = getattr(transport, "remote_version", None) if transport else None
        save_connection(client_ip, resultado, banner=banner,
                        duracion=time.time() - inicio, intentos=server.intentos, detalle=detalle)
        try:
            if transport:
                transport.close()
        except Exception:
            pass
        client_socket.close()

def start_dashboard():
    """Arranca el dashboard Flask en un hilo separado."""
    try:
        from dashboard import socketio, app
        print("🖥️  Dashboard activo en http://0.0.0.0:5000")
        socketio.run(app, debug=False, host="0.0.0.0", port=5000, use_reloader=False, allow_unsafe_werkzeug=True)
    except Exception as e:
        print(f"⚠️  Dashboard no pudo iniciar: {e}")

def start_honeypot():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(MAX_CONNECTIONS)

    print(f"🍯 Honeypot SSH activo en puerto {PORT}. Esperando atacantes...")
    print("   Escribí 'stats' y Enter para ver el resumen")
    print("   Escribí 'exit' y Enter para cerrar\n")

    from config import HTTP_ENABLED, FTP_ENABLED
    from http_honeypot import start_http_honeypot
    from ftp_honeypot import start_ftp_honeypot

    if HTTP_ENABLED:
        threading.Thread(target=start_http_honeypot, daemon=True).start()
    if FTP_ENABLED:
        threading.Thread(target=start_ftp_honeypot, daemon=True).start()

    # Arrancar dashboard automáticamente
    threading.Thread(target=start_dashboard, daemon=True).start()

    def escuchar_comandos():
        while True:
            try:
                comando = input()
                if comando.strip().lower() == "stats":
                    show_stats()
                elif comando.strip().lower() == "exit":
                    print("\nCerrando honeypot...")
                    show_stats()
                    import os
                    os._exit(0)
            except Exception:
                break

    hilo_comandos = threading.Thread(target=escuchar_comandos, daemon=True)
    hilo_comandos.start()

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_ip = client_address[0]
            thread = threading.Thread(
                target=handle_connection,
                args=(client_ip, client_socket)
            )
            thread.daemon = True
            thread.start()

    except KeyboardInterrupt:
        print("\n\nDeteniendo honeypot...")
        show_stats()

    finally:
        server_socket.close()

if __name__ == "__main__":
    start_honeypot()

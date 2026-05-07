import socket
import threading
import paramiko
from logger import save_attempt
from config import HOST, PORT, BANNER, MAX_CONNECTIONS
from stats import show_stats
from fake_shell import FakeShell, manejar_shell

host_key = paramiko.RSAKey.generate(2048)

def handle_connection(client_socket, client_ip):
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = BANNER
        transport.add_server_key(host_key)

        server = FakeShell(client_ip)
        transport.start_server(server=server)

        # Capturar el banner DESPUÉS de la negociación
        try:
            from fingerprint import registrar_banner
            remote_version = transport.remote_version
            if remote_version:
                registrar_banner(client_ip, remote_version)
        except Exception:
            pass

        channel = transport.accept(20)
        if channel is None:
            return

        server.event.wait(10)
        if not server.event.is_set():
            return

        username = getattr(server, "username", "unknown")
        manejar_shell(channel, client_ip, username)

    except Exception:
        pass
    finally:
        client_socket.close()

def start_honeypot():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(MAX_CONNECTIONS)

    print(f"🍯 Honeypot SSH activo en puerto {PORT}. Esperando atacantes...")
    print("   Escribí 'stats' y Enter para ver el resumen")
    print("   Escribí 'exit' y Enter para cerrar\n")

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
                args=(client_socket, client_ip)
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
import socket
import threading
import paramiko
from logger import save_attempt
from config import HOST, PORT, BANNER, MAX_CONNECTIONS
from stats import show_stats

host_key = paramiko.RSAKey.generate(2048)

class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip

    def check_auth_password(self, username, password):
        save_attempt(self.client_ip, username, password)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

def handle_connection(client_socket, client_ip):
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = BANNER
        transport.add_server_key(host_key)
        server = HoneypotServer(client_ip)
        transport.start_server(server=server)
        transport.join(timeout=10)
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

    # Hilo separado para escuchar comandos mientras el honeypot corre
    def escuchar_comandos():
        while True:
            try:
                comando = input()
                if comando.strip().lower() == "stats":
                    show_stats()
                elif comando.strip().lower() == "exit":
                    print("\nCerrando honeypot...")
                    show_stats()
                    os._exit(0)
            except Exception:
                break

    import os
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
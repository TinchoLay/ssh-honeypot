import socket
import threading
import paramiko
from logger import save_attempt
from config import HOST, PORT, BANNER, MAX_CONNECTIONS

# Generar una clave SSH para el servidor
host_key = paramiko.RSAKey.generate(2048)

class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip

    def check_auth_password(self, username, password):
        # Registrar el intento
        save_attempt(self.client_ip, username, password)
        # Siempre rechazar el login
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
        
        # Mantener conexión abierta un momento
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
    print("   Presioná Ctrl+C para detener\n")
    
    while True:
        client_socket, client_address = server_socket.accept()
        client_ip = client_address[0]
        
        # Manejar cada conexión en un hilo separado
        thread = threading.Thread(
            target=handle_connection,
            args=(client_socket, client_ip)
        )
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    start_honeypot()
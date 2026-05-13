import socket
import threading
import json
import os
from datetime import datetime
from config import HOST, FTP_PORT, FTP_LOG

# Respuestas FTP estándar — el protocolo FTP usa códigos numéricos
# igual que HTTP. Estos son los mensajes reales que manda un servidor FTP.
BANNER_FTP = "220 ProFTPD 1.3.5e Server (Debian) ready.\r\n"
RESP_USER  = "331 Password required for {user}\r\n"
RESP_FAIL  = "530 Login incorrect.\r\n"
RESP_OK    = "230 User {user} logged in.\r\n"  # Nunca se usa, siempre falla
RESP_QUIT  = "221 Goodbye.\r\n"
RESP_UNKNOWN = "500 Unknown command.\r\n"

def save_ftp_attempt(ip, username, password):
    """Guarda un intento FTP en el log."""
    os.makedirs("logs", exist_ok=True)
    
    attempt = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "username": username,
        "password": password
    }
    
    with open(FTP_LOG, "a") as f:
        json.dump(attempt, f)
        f.write("\n")
    
    print(f"[FTP]  [{attempt['timestamp']}] {ip} → {username}:{password}")

    # Notificar al dashboard
    try:
        from dashboard import notify_new_attempt
        notify_new_attempt(attempt)
    except Exception:
        pass

def manejar_ftp(client_socket, client_ip):
    """
    Maneja una sesión FTP completa.
    El protocolo FTP funciona así:
    1. Servidor manda banner de bienvenida
    2. Cliente manda USER <nombre>
    3. Servidor pide contraseña
    4. Cliente manda PASS <contraseña>
    5. Servidor acepta o rechaza
    """
    try:
        client_socket.settimeout(30)
        
        # Mandar banner de bienvenida
        client_socket.send(BANNER_FTP.encode())
        
        username = None
        
        while True:
            try:
                data = client_socket.recv(1024).decode("utf-8", errors="ignore").strip()
                
                if not data:
                    break
                
                # Parsear comando FTP
                partes = data.split(" ", 1)
                comando = partes[0].upper()
                argumento = partes[1] if len(partes) > 1 else ""
                
                if comando == "USER":
                    username = argumento
                    client_socket.send(RESP_USER.format(user=username).encode())
                
                elif comando == "PASS":
                    password = argumento
                    if username:
                        save_ftp_attempt(client_ip, username, password)
                    # Siempre rechazar
                    client_socket.send(RESP_FAIL.encode())
                    username = None  # Reset para siguiente intento
                
                elif comando == "QUIT":
                    client_socket.send(RESP_QUIT.encode())
                    break
                
                else:
                    client_socket.send(RESP_UNKNOWN.encode())
            
            except socket.timeout:
                break
    
    except Exception:
        pass
    finally:
        client_socket.close()

def start_ftp_honeypot():
    """Inicia el servidor FTP honeypot."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, FTP_PORT))
    server.listen(5)
    
    print(f"📁 FTP Honeypot activo en puerto {FTP_PORT}")
    
    while True:
        try:
            client_socket, client_address = server.accept()
            thread = threading.Thread(
                target=manejar_ftp,
                args=(client_socket, client_address[0]),
                daemon=True
            )
            thread.start()
        except Exception:
            break
# Configuración del honeypot
HOST = "0.0.0.0"       # Escucha en todas las interfaces
PORT = 2222            # Puerto falso de SSH
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"  # Se hace pasar por Ubuntu
LOG_FILE = "logs/attempts.json"
MAX_CONNECTIONS = 5    # Conexiones simultáneas máximas

import json
import os
from datetime import datetime

def save_attempt(ip, username, password):
    # Crear carpeta logs si no existe
    os.makedirs("logs", exist_ok=True)
    
    attempt = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "username": username,
        "password": password
    }
    
    # Guardar en el archivo JSON
    with open("logs/attempts.json", "a") as f:
        json.dump(attempt, f)
        f.write("\n")
    
    # Mostrar en consola
    print(f"[{attempt['timestamp']}] Intento desde {ip} → usuario: {username} | contraseña: {password}")
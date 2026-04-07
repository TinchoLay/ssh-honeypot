import json
import os
import requests
from datetime import datetime
from config import LOG_FILE, GEO_API_URL, GEO_ENABLED

def get_geolocation(ip):
    # IPs locales no se pueden geolocalizar
    if ip.startswith("127.") or ip.startswith("192.168.") or ip == "localhost":
        return {"country": "Local", "city": "Local", "isp": "Local"}
    
    try:
        response = requests.get(f"{GEO_API_URL}{ip}", timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country", "Desconocido"),
                "city": data.get("city", "Desconocido"),
                "isp": data.get("isp", "Desconocido")
            }
    except Exception:
        pass
    
    return {"country": "Desconocido", "city": "Desconocido", "isp": "Desconocido"}

def save_attempt(ip, username, password):
    os.makedirs("logs", exist_ok=True)
    
    # Obtener geolocalización si está activada
    geo = get_geolocation(ip) if GEO_ENABLED else {"country": "-", "city": "-", "isp": "-"}
    
    attempt = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
        "username": username,
        "password": password
    }
    
    with open(LOG_FILE, "a") as f:
        json.dump(attempt, f)
        f.write("\n")
    
    # Consola con bandera del país
    print(f"[{attempt['timestamp']}] {ip} ({geo['country']} - {geo['city']}) → {username}:{password}")
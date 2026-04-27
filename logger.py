import json
import os
import requests
from datetime import datetime
from config import LOG_FILE, GEO_API_URL, GEO_ENABLED
from alertas import check_y_alertar

def get_geolocation(ip):
    if ip.startswith("127.") or ip.startswith("192.168.") or ip == "localhost":
        return {
            "country": "Local",
            "city": "Local",
            "isp": "Local",
            "lat": None,
            "lon": None
        }
    
    try:
        response = requests.get(f"{GEO_API_URL}{ip}", timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country", "Desconocido"),
                "city": data.get("city", "Desconocido"),
                "isp": data.get("isp", "Desconocido"),
                "lat": data.get("lat"),
                "lon": data.get("lon")
            }
    except Exception:
        pass
    
    return {
        "country": "Desconocido",
        "city": "Desconocido",
        "isp": "Desconocido",
        "lat": None,
        "lon": None
    }

def save_attempt(ip, username, password):
    os.makedirs("logs", exist_ok=True)
    
    geo = get_geolocation(ip) if GEO_ENABLED else {
        "country": "-", "city": "-",
        "isp": "-", "lat": None, "lon": None
    }
    
    attempt = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
        "lat": geo["lat"],
        "lon": geo["lon"],
        "username": username,
        "password": password
    }
    
    with open(LOG_FILE, "a") as f:
        json.dump(attempt, f)
        f.write("\n")
    
    # Verificar si hay que mandar alerta de fuerza bruta
    check_y_alertar(ip, geo["country"], geo["city"], username, password)
    
    # Notificar al dashboard si está corriendo
    try:
        from dashboard import notify_new_attempt
        notify_new_attempt(attempt)
    except Exception:
        pass
    
    print(f"[{attempt['timestamp']}] {ip} ({geo['country']} - {geo['city']}) → {username}:{password}")
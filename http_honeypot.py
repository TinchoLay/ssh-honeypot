import socket
import re
import threading
import json
import os
from datetime import datetime
from config import HOST, HTTP_PORT, HTTP_LOG, GEO_ENABLED

# Página de login falsa — parece un router o panel de admin real
LOGIN_PAGE = """HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html>
<html>
<head>
    <title>Router Admin Panel</title>
    <style>
        body { background: #1a1a2e; display: flex; justify-content: center; 
               align-items: center; height: 100vh; margin: 0; font-family: Arial; }
        .box { background: #16213e; padding: 40px; border-radius: 8px; 
               border: 1px solid #0f3460; width: 300px; }
        h2 { color: #e94560; text-align: center; margin-bottom: 24px; }
        input { width: 100%; padding: 10px; margin: 8px 0; background: #0f3460;
                border: 1px solid #e94560; color: white; border-radius: 4px; 
                box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #e94560; color: white;
                 border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .brand { color: #888; text-align: center; font-size: 12px; margin-top: 16px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>🔒 Admin Login</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <p class="brand">TP-Link Router Management v2.1.4</p>
    </div>
</body>
</html>
"""

# Respuesta cuando intenta hacer login — siempre falla
LOGIN_FAILED = """HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html>
<html>
<head>
    <title>Router Admin Panel</title>
    <style>
        body { background: #1a1a2e; display: flex; justify-content: center;
               align-items: center; height: 100vh; margin: 0; font-family: Arial; }
        .box { background: #16213e; padding: 40px; border-radius: 8px;
               border: 1px solid #0f3460; width: 300px; }
        h2 { color: #e94560; text-align: center; }
        .error { color: #e94560; text-align: center; margin: 16px 0; }
        input { width: 100%; padding: 10px; margin: 8px 0; background: #0f3460;
                border: 1px solid #e94560; color: white; border-radius: 4px;
                box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #e94560; color: white;
                 border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>🔒 Admin Login</h2>
        <p class="error">❌ Invalid credentials. Try again.</p>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

def _geo_http(ip):
    """Geolocaliza la IP con get_geolocation del logger SSH (que cachea por IP)."""
    sin_geo = {"country": "-", "city": "-", "isp": "-", "lat": None, "lon": None}
    if not GEO_ENABLED:
        return sin_geo
    try:
        from logger import get_geolocation
        return get_geolocation(ip)
    except Exception:
        return sin_geo

def save_http_attempt(ip, method, path, username=None, password=None, user_agent="", body=""):
    """Guarda un intento HTTP en el log."""
    os.makedirs("logs", exist_ok=True)
    
    geo = _geo_http(ip)

    attempt = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "honeypot_event": "http_request",
        "ip": ip,
        "method": method,
        "path": path,
        "username": username,
        "password": password,
        "user_agent": user_agent,
        # Cuerpo del request (truncado): ahi viajan los comandos de exploits tipo GPON
        "http_body": body[:2000],
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
        "lat": geo["lat"],
        "lon": geo["lon"]
    }
    
    with open(HTTP_LOG, "a") as f:
        json.dump(attempt, f)
        f.write("\n")
    
    if username:
        print(f"[HTTP] [{attempt['timestamp']}] {ip} → {username}:{password}")
    else:
        print(f"[HTTP] [{attempt['timestamp']}] {ip} → {method} {path}")

    # Notificar al dashboard
    try:
        from dashboard import notify_new_attempt
        notify_new_attempt(attempt)
    except Exception:
        pass

def parsear_request(raw):
    """Parsea un request HTTP crudo y extrae los datos importantes."""
    try:
        lines = raw.split("\r\n")
        if not lines:
            return None, None, None, None, None, ""
        
        # Primera línea: GET /path HTTP/1.1
        primera = lines[0].split(" ")
        method = primera[0] if len(primera) > 0 else "?"
        path = primera[1] if len(primera) > 1 else "/"
        
        # Buscar User-Agent
        user_agent = ""
        for line in lines:
            if line.lower().startswith("user-agent:"):
                user_agent = line.split(":", 1)[1].strip()
                break
        
        # Si es POST, extraer el body
        username = None
        password = None
        body = ""
        if "\r\n\r\n" in raw:
            body = raw.split("\r\n\r\n", 1)[1]
        if method == "POST" and body:
            # Parsear campos del form: username=root&password=1234
            params = {}
            for param in body.split("&"):
                if "=" in param:
                    k, v = param.split("=", 1)
                    params[k.strip()] = v.strip()
            
            username = params.get("username") or params.get("user") or params.get("login")
            password = params.get("password") or params.get("pass") or params.get("pwd")
        
        return method, path, user_agent, username, password, body
    
    except Exception:
        return None, None, None, None, None, ""

def leer_request(client_socket):
    """Lee el request. Si es un POST espera el cuerpo segun Content-Length (tope 8 KB)."""
    data = client_socket.recv(4096)
    if not data:
        return ""
    if data.startswith(b"POST") and b"\r\n\r\n" in data:
        head, _, body = data.partition(b"\r\n\r\n")
        m = re.search(rb"content-length:\s*(\d+)", head, re.I)
        if m:
            faltan = min(int(m.group(1)), 8192) - len(body)
            while faltan > 0:
                try:
                    chunk = client_socket.recv(min(faltan, 4096))
                except Exception:
                    break
                if not chunk:
                    break
                data += chunk
                faltan -= len(chunk)
    return data.decode("utf-8", errors="ignore")

def manejar_http(client_socket, client_ip):
    """Maneja una conexión HTTP entrante."""
    try:
        client_socket.settimeout(10)
        raw = leer_request(client_socket)
        
        if not raw:
            return
        
        method, path, user_agent, username, password, body = parsear_request(raw)
        
        if method is None:
            return
        
        # Registrar el intento
        save_http_attempt(client_ip, method, path, username, password, user_agent, body)
        
        # Responder según el tipo de request
        if method == "POST" and path in ["/login", "/admin", "/signin"]:
            client_socket.send(LOGIN_FAILED.encode())
        else:
            client_socket.send(LOGIN_PAGE.encode())
    
    except Exception:
        pass
    finally:
        client_socket.close()

def start_http_honeypot():
    """Inicia el servidor HTTP honeypot."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, HTTP_PORT))
    server.listen(5)
    
    print(f"🌐 HTTP Honeypot activo en puerto {HTTP_PORT}")
    
    while True:
        try:
            client_socket, client_address = server.accept()
            thread = threading.Thread(
                target=manejar_http,
                args=(client_socket, client_address[0]),
                daemon=True
            )
            thread.start()
        except Exception:
            break
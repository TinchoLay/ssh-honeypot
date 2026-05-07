import re
from datetime import datetime, timedelta
from collections import defaultdict
import json
import os

FINGERPRINT_LOG = "logs/fingerprints.json"

# Base de datos de firmas conocidas
# Cada entrada tiene el patrón a buscar en el banner y el nombre de la herramienta
FIRMAS = [
    # Herramientas de fuerza bruta
    {"patron": r"libssh",           "herramienta": "Hydra",         "tipo": "Brute Force"},
    {"patron": r"paramiko",         "herramienta": "Paramiko/Python","tipo": "Script custom"},
    {"patron": r"Net::SSH",         "herramienta": "Metasploit",    "tipo": "Framework ofensivo"},
    {"patron": r"Ruby",             "herramienta": "Ruby SSH client","tipo": "Script custom"},
    {"patron": r"JSCH",             "herramienta": "JSch/Java",     "tipo": "Script Java"},
    {"patron": r"Granados",         "herramienta": "Poderosa",      "tipo": "SSH client"},
    {"patron": r"AsyncSSH",         "herramienta": "AsyncSSH",      "tipo": "Script Python"},
    {"patron": r"Dropbear",         "herramienta": "Dropbear",      "tipo": "SSH embebido"},
    {"patron": r"PuTTY",            "herramienta": "PuTTY",         "tipo": "Cliente legítimo"},
    {"patron": r"FileZilla",        "herramienta": "FileZilla",     "tipo": "FTP/SFTP client"},
    {"patron": r"WinSCP",           "herramienta": "WinSCP",        "tipo": "Cliente legítimo"},
    {"patron": r"OpenSSH",          "herramienta": "OpenSSH",       "tipo": "Cliente estándar"},
    {"patron": r"Go",               "herramienta": "Go SSH client", "tipo": "Script Go"},
    {"patron": r"Nmap",             "herramienta": "Nmap",          "tipo": "Scanner"},
    {"patron": r"masscan",          "herramienta": "Masscan",       "tipo": "Scanner"},
    {"patron": r"libssh2",          "herramienta": "libssh2",       "tipo": "Brute Force"},
]

# Registro de tiempos de intentos por IP para análisis de velocidad
_tiempos_intentos = defaultdict(list)
_banners_vistos = {}

def registrar_banner(ip, banner):
    """Guarda el banner SSH del cliente."""
    _banners_vistos[ip] = banner

def identificar_herramienta(banner):
    """Identifica la herramienta basándose en el banner SSH."""
    if not banner:
        return {"herramienta": "Desconocida", "tipo": "?", "confianza": "Baja"}
    
    for firma in FIRMAS:
        if re.search(firma["patron"], banner, re.IGNORECASE):
            return {
                "herramienta": firma["herramienta"],
                "tipo": firma["tipo"],
                "confianza": "Alta"
            }
    
    return {"herramienta": "Desconocida", "tipo": "Cliente no identificado", "confianza": "Baja"}

def analizar_velocidad(ip):
    """
    Analiza qué tan rápido hace intentos la IP.
    Los bots son muy rápidos y regulares, los humanos son lentos e irregulares.
    """
    ahora = datetime.now()
    _tiempos_intentos[ip].append(ahora)
    
    # Solo analizamos si hay al menos 3 intentos
    intentos = _tiempos_intentos[ip]
    if len(intentos) < 3:
        return {"tipo": "Desconocido", "intentos_por_minuto": 0, "es_bot": False}
    
    # Calcular intentos por minuto en la ventana de los últimos 60 segundos
    ventana = ahora - timedelta(seconds=60)
    recientes = [t for t in intentos if t > ventana]
    intentos_por_minuto = len(recientes)
    
    # Calcular la variación en el tiempo entre intentos
    # Los bots tienen intervalos muy regulares (baja variación)
    # Los humanos tienen intervalos irregulares (alta variación)
    if len(intentos) >= 3:
        intervalos = []
        for i in range(1, len(intentos[-5:])):
            delta = (intentos[-5:][i] - intentos[-5:][i-1]).total_seconds()
            intervalos.append(delta)
        
        if intervalos:
            promedio = sum(intervalos) / len(intervalos)
            variacion = max(intervalos) - min(intervalos)
            
            # Bot: muchos intentos rápidos con poca variación
            if intentos_por_minuto >= 10 and variacion < 2:
                tipo = "Bot automatizado (alta velocidad)"
                es_bot = True
            elif intentos_por_minuto >= 5:
                tipo = "Posible bot (velocidad media)"
                es_bot = True
            else:
                tipo = "Posible humano (velocidad baja)"
                es_bot = False
        else:
            tipo = "Analizando..."
            es_bot = False
    else:
        tipo = "Insuficientes datos"
        es_bot = False
    
    return {
        "tipo": tipo,
        "intentos_por_minuto": intentos_por_minuto,
        "es_bot": es_bot
    }

def analizar_patron_credenciales(ip, username, password):
    """
    Detecta patrones en las credenciales probadas.
    Hydra y herramientas similares usan diccionarios en orden fijo.
    """
    # Credenciales más comunes usadas por bots
    usuarios_bot = {"root", "admin", "user", "test", "ubuntu", "pi", "oracle", "postgres"}
    passwords_comunes = {"123456", "password", "admin", "root", "12345", "1234", "test"}
    
    patron = []
    
    if username.lower() in usuarios_bot:
        patron.append("usuario de diccionario común")
    
    if password.lower() in passwords_comunes:
        patron.append("contraseña de diccionario común")
    
    if username == password:
        patron.append("usuario=contraseña (patrón típico de bot)")
    
    if len(password) <= 4:
        patron.append("contraseña muy corta")
    
    return patron

def hacer_fingerprint(ip, username, password):
    """
    Función principal — analiza todo y genera el fingerprint completo.
    Llamala desde logger.py en cada intento.
    """
    # IPs locales no se analizan
    if ip.startswith("127.") or ip.startswith("192.168."):
        return None
    
    banner = _banners_vistos.get(ip, "")
    herramienta = identificar_herramienta(banner)
    velocidad = analizar_velocidad(ip)
    patron = analizar_patron_credenciales(ip, username, password)
    
    resultado = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "banner": banner,
        "herramienta": herramienta["herramienta"],
        "tipo_herramienta": herramienta["tipo"],
        "confianza": herramienta["confianza"],
        "velocidad": velocidad,
        "patron_credenciales": patron
    }
    
    # Guardar en log
    os.makedirs("logs", exist_ok=True)
    with open(FINGERPRINT_LOG, "a") as f:
        json.dump(resultado, f)
        f.write("\n")
    
    # Mostrar en consola solo si hay info interesante
    if herramienta["herramienta"] != "Desconocida" or velocidad["es_bot"]:
        mostrar_fingerprint(resultado)
    
    return resultado

def mostrar_fingerprint(r):
    """Muestra el fingerprint en consola."""
    print(f"\n  {'─'*45}")
    print(f"  🔎 Fingerprint — {r['ip']}")
    print(f"  Herramienta:  {r['herramienta']} ({r['tipo_herramienta']})")
    print(f"  Confianza:    {r['confianza']}")
    if r['banner']:
        print(f"  Banner SSH:   {r['banner']}")
    
    vel = r['velocidad']
    if vel['intentos_por_minuto'] > 0:
        emoji = "🤖" if vel['es_bot'] else "👤"
        print(f"  Velocidad:    {emoji} {vel['intentos_por_minuto']} intentos/min — {vel['tipo']}")
    
    if r['patron_credenciales']:
        print(f"  Patrón:       {', '.join(r['patron_credenciales'])}")
    
    print(f"  {'─'*45}\n")
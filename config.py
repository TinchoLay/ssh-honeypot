# Configuración del honeypot
HOST = "0.0.0.0"       # Escucha en todas las interfaces
PORT = 2222            # Puerto falso de SSH
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"  # Se hace pasar por Ubuntu
LOG_FILE = "logs/attempts.json"
MAX_CONNECTIONS = 5    # Conexiones simultáneas máximas

import os

# Geolocalización
GEO_API_URL = "http://ip-api.com/json/"
GEO_ENABLED = os.getenv("GEO_ENABLED", "true").lower() == "true"

# Alertas por email
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "")
EMAIL_SMTP = "smtp.gmail.com"
EMAIL_PORT = 587
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "5"))
ALERT_WINDOW = int(os.getenv("ALERT_WINDOW", "60"))

# Threat Intelligence
THREAT_INTEL_ENABLED = os.getenv("THREAT_INTEL_ENABLED", "false").lower() == "true"
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
SHODAN_KEY = os.getenv("SHODAN_KEY", "")
THREAT_LOG = "logs/threat_intel.json"

# Multi-servicio
HTTP_PORT = 8080
FTP_PORT = 2121
HTTP_ENABLED = True
FTP_ENABLED = True
HTTP_LOG = "logs/http_attempts.json"
FTP_LOG = "logs/ftp_attempts.json"

# Captura de malware
MALWARE_ENABLED = True
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")
MALWARE_DIR = "logs/malware_samples"
MALWARE_LOG = "logs/malware_captures.json"

# IPs propias (tuyas) que el honeypot NO registra: no se escriben en ningun log ni se
# geolocalizan. Se define con la variable HONEYPOT_IGNORE_IPS, separada por comas, y admite
# IPs sueltas o redes en notacion CIDR. Ej: HONEYPOT_IGNORE_IPS=203.0.113.5,198.51.100.0/24
# Ojo: una red grande (un /24 de tu proveedor) tambien ignora a otros clientes del mismo
# proveedor. Preferi IPs exactas.
import ipaddress

def _cargar_ips_ignoradas():
    redes = []
    for crudo in os.getenv("HONEYPOT_IGNORE_IPS", "").split(","):
        crudo = crudo.strip()
        if not crudo:
            continue
        try:
            redes.append(ipaddress.ip_network(crudo, strict=False))
        except ValueError:
            print(f"[config] HONEYPOT_IGNORE_IPS: valor invalido ignorado: {crudo!r}")
    return redes

IGNORE_NETS = _cargar_ips_ignoradas()

def es_ip_propia(ip):
    """True si la IP esta en la lista de IPs propias a ignorar."""
    if not IGNORE_NETS:
        return False
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(direccion in red for red in IGNORE_NETS)

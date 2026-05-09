# Configuración del honeypot
HOST = "0.0.0.0"       # Escucha en todas las interfaces
PORT = 2222            # Puerto falso de SSH
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"  # Se hace pasar por Ubuntu
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
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "88bfd6d31fdfe7d74a9c29d6290d480b585c77c7e7b46cd1e42ac0c280f4fdae")
MALWARE_DIR = "logs/malware_samples"
MALWARE_LOG = "logs/malware_captures.json"

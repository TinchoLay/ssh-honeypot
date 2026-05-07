# Configuración del honeypot
HOST = "0.0.0.0"       # Escucha en todas las interfaces
PORT = 2222            # Puerto falso de SSH
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"  # Se hace pasar por Ubuntu
LOG_FILE = "logs/attempts.json"
MAX_CONNECTIONS = 5    # Conexiones simultáneas máximas
# Geolocalización
GEO_API_URL = "http://ip-api.com/json/"
GEO_ENABLED = True
# Alertas por email
EMAIL_ENABLED = True
EMAIL_SENDER = "martinjchancalay@gmail.com"
EMAIL_PASSWORD = "qzyo bmav ddoi qmgk"
EMAIL_RECEIVER = "martinjchancalay@gmail.com"
EMAIL_SMTP = "smtp.gmail.com"
EMAIL_PORT = 587
ALERT_THRESHOLD = 2
ALERT_WINDOW = 60
# Threat Intelligence
THREAT_INTEL_ENABLED = True
ABUSEIPDB_KEY = "b8e27b1781fa95a90f0dd4f1914265f50076180570441187f42fc95080f5c8358b16c600b8529844"
SHODAN_KEY = "r20OrG5hZpiJSmap5G7jNIlpBYqJe2Z8"
THREAT_LOG = "logs/threat_intel.json"
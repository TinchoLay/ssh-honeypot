import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from collections import defaultdict
from config import (
    EMAIL_ENABLED, EMAIL_SENDER, EMAIL_PASSWORD,
    EMAIL_RECEIVER, EMAIL_SMTP, EMAIL_PORT,
    ALERT_THRESHOLD, ALERT_WINDOW
)

# Diccionario que registra los intentos por IP con su timestamp
# defaultdict(list) crea automáticamente una lista vacía para cada IP nueva
intentos_por_ip = defaultdict(list)

# Set de IPs que ya recibieron alerta para no spamear
ips_alertadas = set()

def registrar_intento(ip):
    """Registra un intento y verifica si hay que mandar alerta."""
    ahora = datetime.now()
    
    # Agregar el timestamp actual a la lista de intentos de esta IP
    intentos_por_ip[ip].append(ahora)
    
    # Limpiar intentos viejos (fuera de la ventana de tiempo)
    # Solo nos quedamos con los que están dentro de los últimos ALERT_WINDOW segundos
    ventana = ahora - timedelta(seconds=ALERT_WINDOW)
    intentos_por_ip[ip] = [t for t in intentos_por_ip[ip] if t > ventana]
    
    # Verificar si superó el umbral y no fue alertada antes
    cantidad = len(intentos_por_ip[ip])
    if cantidad >= ALERT_THRESHOLD and ip not in ips_alertadas:
        return True, cantidad
    
    return False, cantidad

def enviar_alerta(ip, country, city, username, password, cantidad):
    """Envía el email de alerta."""
    if not EMAIL_ENABLED:
        return
    
    # Crear el mensaje
    msg = MIMEMultipart()
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER
    msg["Subject"] = f"⚠️ ALERTA Honeypot: Fuerza bruta desde {ip}"
    
    cuerpo = f"""
    ⚠️  ATAQUE DE FUERZA BRUTA DETECTADO
    ════════════════════════════════════
    
    IP atacante:     {ip}
    País / Ciudad:   {country} - {city}
    Intentos:        {cantidad} en los últimos {ALERT_WINDOW} segundos
    
    Último intento:
      Usuario:       {username}
      Contraseña:    {password}
    
    Timestamp:       {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    
    ════════════════════════════════════
    SSH Honeypot — Sistema de alertas automáticas
    """
    
    msg.attach(MIMEText(cuerpo, "plain"))
    
    try:
        # Conectar al servidor SMTP de Gmail
        servidor = smtplib.SMTP(EMAIL_SMTP, EMAIL_PORT)
        servidor.starttls()  # Activar cifrado TLS
        servidor.login(EMAIL_SENDER, EMAIL_PASSWORD)
        servidor.send_message(msg)
        servidor.quit()
        
        # Marcar la IP como alertada para no volver a mandar email
        ips_alertadas.add(ip)
        print(f"  📧 Alerta enviada por email — IP: {ip} ({cantidad} intentos)")
        
    except Exception as e:
        print(f"  ❌ Error al enviar alerta: {e}")

def check_y_alertar(ip, country, city, username, password):
    """Función principal — llamala desde logger.py en cada intento."""
    # IPs locales no generan alertas
    if ip.startswith("127.") or ip.startswith("192.168."):
        return
    
    disparar, cantidad = registrar_intento(ip)
    
    if disparar:
        enviar_alerta(ip, country, city, username, password, cantidad)
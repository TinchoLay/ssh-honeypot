import json
import os
from datetime import datetime
from ml_classifier import registrar_shell_ml
from config import es_ip_propia

SHELL_LOG = "logs/shell_commands.json"

def save_command(ip, command, nota="", canal="shell"):
    """Guarda un comando ejecutado por el atacante.
    canal: "shell" (sesion interactiva) o "exec" (comando directo: ssh host "cmd")."""
    if es_ip_propia(ip):
        return
    os.makedirs("logs", exist_ok=True)
    
    registro = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "honeypot_event": "shell_command",
        "ip": ip,
        "command": command,
        "canal": canal,
        "nota": nota
    }
    
    with open(SHELL_LOG, "a") as f:
        json.dump(registro, f)
        f.write("\n")
    
    registrar_shell_ml(ip, command)
    
    if nota:
        print(f"\n  ⚠️  {nota} — IP: {ip}")
    else:
        print(f"  💻 [{ip}] Comando: {command}")
import json
import os
from datetime import datetime
from ml_classifier import registrar_shell_ml

SHELL_LOG = "logs/shell_commands.json"

def save_command(ip, command, nota=""):
    """Guarda un comando ejecutado por el atacante."""
    os.makedirs("logs", exist_ok=True)
    
    registro = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "command": command,
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
import json
import os
import requests
import shodan
from datetime import datetime
from config import (
    THREAT_INTEL_ENABLED, ABUSEIPDB_KEY,
    SHODAN_KEY, THREAT_LOG
)

# Cache para no consultar la misma IP dos veces
# Si una IP ya fue consultada, usamos el resultado guardado
_cache = {}

def consultar_abuseipdb(ip):
    """Consulta AbuseIPDB para saber si la IP fue reportada."""
    try:
        headers = {
            "Key": ABUSEIPDB_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90    # Reportes de los últimos 90 días
        }
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=5
        )
        data = response.json().get("data", {})
        
        return {
            "reportes": data.get("totalReports", 0),
            "confianza": data.get("abuseConfidenceScore", 0),
            "pais": data.get("countryCode", "?"),
            "isp": data.get("isp", "?"),
            "tipo": data.get("usageType", "?"),
            "ultimo_reporte": data.get("lastReportedAt", "?")
        }
    except Exception as e:
        return {"error": str(e)}

def consultar_shodan(ip):
    """Consulta Shodan para obtener info del host."""
    try:
        api = shodan.Shodan(SHODAN_KEY)
        host = api.host(ip)
        
        # Extraer puertos abiertos
        puertos = [str(s["port"]) for s in host.get("data", [])]
        
        # Extraer tags (tor, scanner, malicious, etc.)
        tags = host.get("tags", [])
        
        # Extraer vulnerabilidades conocidas si las hay
        vulns = list(host.get("vulns", {}).keys())
        
        return {
            "puertos": puertos,
            "tags": tags,
            "vulnerabilidades": vulns[:5],  # Máximo 5
            "sistema_operativo": host.get("os", "Desconocido"),
            "organizacion": host.get("org", "?"),
            "ultima_actualizacion": host.get("last_update", "?")
        }
    except shodan.APIError:
        # IP no encontrada en Shodan — no es un error, simplemente no está indexada
        return {"encontrado": False}
    except Exception as e:
        return {"error": str(e)}

def analizar_ip(ip):
    """Función principal — consulta ambas APIs y guarda el resultado."""
    
    # IPs locales no se consultan
    if ip.startswith("127.") or ip.startswith("192.168.") or ip == "localhost":
        return None
    
    # Si ya la consultamos antes, devolvemos el cache
    if ip in _cache:
        return _cache[ip]
    
    if not THREAT_INTEL_ENABLED:
        return None
    
    print(f"\n  🔍 Consultando Threat Intel para {ip}...")
    
    resultado = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "abuseipdb": consultar_abuseipdb(ip),
        "shodan": consultar_shodan(ip)
    }
    
    # Guardar en el log
    os.makedirs("logs", exist_ok=True)
    with open(THREAT_LOG, "a") as f:
        json.dump(resultado, f)
        f.write("\n")
    
    # Guardar en cache para no consultar de nuevo
    _cache[ip] = resultado
    
    # Mostrar resumen en consola
    mostrar_resumen(ip, resultado)
    
    return resultado

def mostrar_resumen(ip, resultado):
    """Muestra un resumen del análisis en consola."""
    abuse = resultado.get("abuseipdb", {})
    shodan_data = resultado.get("shodan", {})
    
    print(f"\n  {'═'*45}")
    print(f"  🔍 Threat Intel — {ip}")
    
    # AbuseIPDB
    if "error" not in abuse:
        reportes = abuse.get("reportes", 0)
        confianza = abuse.get("confianza", 0)
        
        # Color según nivel de riesgo
        if confianza >= 80:
            nivel = "🔴 ALTO RIESGO"
        elif confianza >= 40:
            nivel = "🟡 RIESGO MEDIO"
        elif reportes > 0:
            nivel = "🟠 REPORTADA"
        else:
            nivel = "🟢 Sin reportes"
        
        print(f"  AbuseIPDB: {reportes} reportes | {nivel}")
        print(f"  Confianza maliciosa: {confianza}%")
        if abuse.get("ultimo_reporte") != "?":
            print(f"  Último reporte: {abuse.get('ultimo_reporte')}")
    
    # Shodan
    if shodan_data.get("encontrado") is not False and "error" not in shodan_data:
        puertos = shodan_data.get("puertos", [])
        tags = shodan_data.get("tags", [])
        vulns = shodan_data.get("vulnerabilidades", [])
        
        if puertos:
            print(f"  Shodan: {len(puertos)} puertos abiertos ({', '.join(puertos[:5])})")
        if tags:
            print(f"  Tags: {', '.join(tags)}")
        if vulns:
            print(f"  ⚠️  Vulnerabilidades: {', '.join(vulns)}")
    else:
        print(f"  Shodan: IP no indexada")
    
    print(f"  {'═'*45}\n")

def get_threat_summary():
    """Devuelve un resumen de todas las IPs analizadas — para el dashboard."""
    if not os.path.exists(THREAT_LOG):
        return []
    
    resultados = []
    with open(THREAT_LOG, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    resultados.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return resultados
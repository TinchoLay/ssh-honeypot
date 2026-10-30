"""Resumen diario del honeypot, pensado para pegarlo en una conversacion de analisis.

Lee los logs JSON (un evento por linea) y arma un texto corto con lo que paso en una
ventana de tiempo, mas el historial de las IPs que ya habian aparecido antes. Solo usa
la libreria estandar, asi que corre en el servidor sin instalar nada:

    cd ~/honeypot-aws
    python3 resumen_diario.py                 # ultimas 24 horas
    python3 resumen_diario.py --horas 72      # ventana mas larga
    python3 resumen_diario.py --ip a3f9c1     # linea de tiempo completa de una IP

Decisiones de diseno:
- Las IPs salen enmascaradas: "203.0.x.x#a3f9c1". El sufijo es un hash estable, asi la
  misma IP se reconoce de un dia al otro sin publicarla. --sin-mascara las muestra enteras.
- Todo lo que viene del atacante (usuario, clave, comando, ruta HTTP) se limpia de
  caracteres de control y se recorta. Es texto no confiable: si alguien pone una linea
  que parece una instruccion, tiene que llegar como dato, nunca como renglon propio.
- Las banderas son ayuda para decidir que mirar primero. No son conclusiones.
"""
import argparse
import glob
import hashlib
import ipaddress
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

FORMATO = "%Y-%m-%d %H:%M:%S"
EVENTOS = {
    "ssh_login_attempt", "ssh_connection", "shell_command",
    "http_request", "ftp_login_attempt", "malware_capture",
}
# Rutas HTTP que buscan APIs de modelos de IA abiertas
RUTAS_IA = ("/v1/models", "/api/v1/models", "/v1beta/models", "/api/tags")

_RE_HASH = re.compile(r"check_[0-9a-fA-F]{32}")
_RE_ARIT = re.compile(r"\$\(\(\s*\d+\s*\*\s*\d+\s*\+\s*\d+\s*\)\)")


def limpiar(texto, largo=80):
    """Una sola linea, sin caracteres de control, de largo acotado."""
    s = "".join(c if c.isprintable() else "?" for c in str(texto))
    return s if len(s) <= largo else s[: largo - 1] + "…"


def mascara(ip, mostrar=False):
    """203.0.113.7 -> 203.0.x.x#a3f9c1 (el hash identifica la IP completa)."""
    if mostrar:
        return limpiar(ip, 45)
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return limpiar(ip, 40)
    h = hashlib.sha256(ip.encode()).hexdigest()[:6]
    if ":" in ip:
        return f"{ip.split(':')[0]}:x#{h}"
    o = ip.split(".")
    return f"{o[0]}.{o[1]}.x.x#{h}"


def _es_publica(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or a.is_unspecified)


def normalizar_comando(cmd):
    """Agrupa las sondas que solo cambian en el hash o en los numeros al azar."""
    cmd = _RE_HASH.sub("check_<HASH>", str(cmd))
    return _RE_ARIT.sub("$((a*b+c))", cmd)


def cargar_eventos(carpeta):
    """Lee todos los *.json de la carpeta. Ignora lineas rotas y registros de otro tipo
    (por ejemplo threat_intel.json, que no tiene honeypot_event)."""
    eventos = []
    for ruta in sorted(glob.glob(os.path.join(carpeta, "*.json"))):
        try:
            with open(ruta, encoding="utf-8", errors="replace") as f:
                for linea in f:
                    linea = linea.strip()
                    if not linea:
                        continue
                    try:
                        e = json.loads(linea)
                        if not isinstance(e, dict):
                            continue
                        if e.get("honeypot_event") not in EVENTOS or not e.get("ip"):
                            continue
                        e["_t"] = datetime.strptime(e["timestamp"], FORMATO)
                    except (ValueError, KeyError, TypeError):
                        continue
                    e["ip"] = str(e["ip"])
                    eventos.append(e)
        except OSError:
            continue
    eventos.sort(key=lambda e: e["_t"])
    return eventos


def describir(e):
    """Una linea corta por evento, para las lineas de tiempo."""
    t = e["_t"].strftime(FORMATO)
    k = e["honeypot_event"]
    if k == "ssh_login_attempt":
        return f"{t} ssh login {limpiar(e.get('username'), 30)}/{limpiar(e.get('password'), 30)}"
    if k == "ssh_connection":
        return (f"{t} ssh conexion {limpiar(e.get('resultado'), 30)} "
                f"({e.get('duracion_seg')}s, banner {limpiar(e.get('banner'), 30)})")
    if k == "shell_command":
        return f"{t} comando[{limpiar(e.get('canal'), 8)}] {limpiar(normalizar_comando(e.get('command')), 70)}"
    if k == "http_request":
        return f"{t} http {limpiar(e.get('method'), 8)} {limpiar(e.get('path'), 60)}"
    if k == "ftp_login_attempt":
        return f"{t} ftp login {limpiar(e.get('username'), 30)}/{limpiar(e.get('password'), 30)}"
    return f"{t} malware {limpiar(e.get('nombre_archivo'), 40)}"


def _pares(eventos):
    return {(e.get("username"), e.get("password"))
            for e in eventos if e["honeypot_event"] == "ssh_login_attempt"}


def _banderas(ev_v, ev_p):
    """Banderas de triage para una IP, dado lo de la ventana y lo anterior."""
    todos = ev_v + ev_p
    b = []
    if not ev_p:
        b.append("primera vez")
    dias = {e["_t"].date() for e in todos}
    if len(dias) >= 2:
        b.append(f"recurrente ({len(dias)} dias)")
    intentos_dia = Counter(e["_t"].date() for e in todos if e["honeypot_event"] == "ssh_login_attempt")
    if len(dias) >= 2 and intentos_dia and max(intentos_dia.values()) <= 2:
        b.append("ritmo lento")
    if len(_pares(todos)) >= 3 and len(dias) >= 2:
        b.append(f"{len(_pares(todos))} credenciales distintas")
    if any(e["honeypot_event"] == "ssh_connection" and e.get("resultado") == "autenticado_sin_shell"
           for e in ev_v):
        b.append("autentico y se fue")
    if any(e["honeypot_event"] == "shell_command" for e in ev_v):
        b.append("ejecuto comandos")
    if any(e["honeypot_event"] == "malware_capture" for e in ev_v):
        b.append("descarga de malware")
    for e in ev_v:
        if e["honeypot_event"] == "http_request":
            p = str(e.get("path", ""))
            if p.lower().startswith("http") or p in RUTAS_IA:
                b.append("http: proxy/API de IA")
                break
    return b


def _geo(eventos):
    for e in eventos:
        if e.get("country") and e.get("country") not in ("-", "Desconocido"):
            return f"{limpiar(e.get('country'), 20)} / {limpiar(e.get('isp'), 30)}"
    return "?"


def resumir(eventos, desde, hasta, historial_dias=30, top=10, sin_mascara=False,
            ignorar=(), lineas_historial=12, ver_ip=None):
    ign = set(ignorar)
    todos = [e for e in eventos if e["ip"] not in ign and _es_publica(e["ip"])]
    m = lambda ip: mascara(ip, sin_mascara)

    if ver_ip:
        ver_ip = ver_ip.lstrip("#")
        mios = [e for e in todos if e["ip"] == ver_ip or mascara(e["ip"]).endswith("#" + ver_ip)]
        if not mios:
            return f"No hay eventos para {limpiar(ver_ip, 40)}."
        out = [f"LINEA DE TIEMPO {m(mios[0]['ip'])}  ({_geo(mios)})  {len(mios)} eventos"]
        out += ["  " + describir(e) for e in mios]
        return "\n".join(out)

    ventana = [e for e in todos if desde <= e["_t"] <= hasta]
    corte = desde - timedelta(days=historial_dias)
    previos = [e for e in todos if corte <= e["_t"] < desde]

    out = [f"RESUMEN {desde:%Y-%m-%d %H:%M} -> {hasta:%Y-%m-%d %H:%M} (hora del servidor)"]
    if not ventana:
        out.append("Sin actividad en la ventana.")
        return "\n".join(out)

    v_ip, p_ip = defaultdict(list), defaultdict(list)
    for e in ventana:
        v_ip[e["ip"]].append(e)
    for e in previos:
        p_ip[e["ip"]].append(e)

    nuevas = sum(1 for ip in v_ip if ip not in p_ip)
    out.append(f"Eventos: {len(ventana)} | IPs: {len(v_ip)} (nuevas {nuevas}, ya vistas {len(v_ip) - nuevas}"
               f" en {historial_dias} dias)")

    tipos = Counter(e["honeypot_event"] for e in ventana)
    out.append("Por tipo: " + ", ".join(f"{k} {v}" for k, v in tipos.most_common()))
    res = Counter(limpiar(e.get("resultado"), 30) for e in ventana if e["honeypot_event"] == "ssh_connection")
    if res:
        out.append("Resultado de conexiones SSH: " + ", ".join(f"{k} {v}" for k, v in res.most_common()))
    ban = Counter(limpiar(e.get("banner"), 40) for e in ventana
                  if e["honeypot_event"] == "ssh_connection" and e.get("banner"))
    if ban:
        out.append("Banners de cliente: " + ", ".join(f"{k} x{v}" for k, v in ban.most_common(5)))

    # IPs ordenadas por cantidad de banderas y luego por actividad
    filas = []
    for ip, ev in v_ip.items():
        b = _banderas(ev, p_ip.get(ip, []))
        filas.append((len(b), len(ev), ip, b))
    filas.sort(key=lambda f: (-f[0], -f[1]))
    llamativas = [f for f in filas if f[0] > 1 or (f[0] == 1 and "primera vez" not in f[3])]

    out.append("")
    out.append("IPs a mirar primero:")
    if not llamativas:
        out.append("  (ninguna con banderas mas alla de ser nueva)")
    for _, n, ip, b in llamativas[:top]:
        out.append(f"  {m(ip)} | {_geo(v_ip[ip] + p_ip.get(ip, []))} | {n} eventos | " + ", ".join(b))
    resto = len(filas) - min(len(llamativas), top)
    if resto > 0:
        out.append(f"  y {resto} IPs mas sin banderas relevantes (escaneo de una sola vez)")

    # Credenciales
    ssh = [e for e in ventana if e["honeypot_event"] in ("ssh_login_attempt", "ftp_login_attempt")]
    if ssh:
        out.append("")
        users = Counter(limpiar(e.get("username"), 25) for e in ssh)
        out.append("Usuarios mas probados: " + ", ".join(f"{k} x{v}" for k, v in users.most_common(8)))
        vistas = {e.get("password") for e in previos
                  if e["honeypot_event"] in ("ssh_login_attempt", "ftp_login_attempt")}
        nuevas_pw = [limpiar(p, 25) for p in dict.fromkeys(e.get("password") for e in ssh) if p not in vistas]
        out.append(f"Contrasenas nunca vistas antes ({len(nuevas_pw)}): " + ", ".join(nuevas_pw[:12]))

    # Comandos
    cmds = Counter((normalizar_comando(e.get("command")), e.get("canal")) for e in ventana
                   if e["honeypot_event"] == "shell_command")
    if cmds:
        out.append("")
        out.append("Comandos (agrupando sondas por hash y numeros al azar):")
        for (c, canal), n in cmds.most_common(8):
            out.append(f"  x{n} [{limpiar(canal, 8)}] {limpiar(c, 90)}")

    # HTTP
    rutas = Counter(limpiar(e.get("path"), 70) for e in ventana if e["honeypot_event"] == "http_request")
    if rutas:
        out.append("")
        out.append("Rutas HTTP: " + ", ".join(f"{k} x{v}" for k, v in rutas.most_common(8)))
        uas = Counter(limpiar(e.get("user_agent"), 50) for e in ventana
                      if e["honeypot_event"] == "http_request" and e.get("user_agent"))
        if uas:
            out.append("User-Agents: " + ", ".join(f"{k} x{v}" for k, v in uas.most_common(4)))

    # Historial de las IPs recurrentes
    rec = [f for f in llamativas if any(x.startswith("recurrente") for x in f[3])][:top]
    if rec:
        out.append("")
        out.append("Historial de IPs recurrentes (ultimos eventos):")
        for _, _, ip, _ in rec:
            hist = sorted(v_ip[ip] + p_ip.get(ip, []), key=lambda e: e["_t"])
            out.append(f"  {m(ip)}")
            out += ["    " + describir(e) for e in hist[-lineas_historial:]]

    out.append("")
    out.append("Las banderas sirven para decidir que mirar primero; no son conclusiones.")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Resumen diario del honeypot")
    ap.add_argument("--logs", default="logs", help="carpeta con los *.json (por defecto logs)")
    ap.add_argument("--horas", type=float, default=24, help="largo de la ventana (24)")
    ap.add_argument("--hasta", help="fin de la ventana, 'YYYY-MM-DD HH:MM:SS' (ahora)")
    ap.add_argument("--historial-dias", type=int, default=30, help="dias hacia atras para reconocer IPs (30)")
    ap.add_argument("--top", type=int, default=10, help="cuantas IPs listar (10)")
    ap.add_argument("--ip", help="linea de tiempo completa de una IP (el sufijo #hash o la IP)")
    ap.add_argument("--sin-mascara", action="store_true", help="mostrar las IPs completas")
    ap.add_argument("--ignorar", action="append", default=[], help="IP a ignorar (se puede repetir)")
    a = ap.parse_args(argv)

    hasta = datetime.strptime(a.hasta, FORMATO) if a.hasta else datetime.now()
    desde = hasta - timedelta(hours=a.horas)
    eventos = cargar_eventos(a.logs)
    print(resumir(eventos, desde, hasta, historial_dias=a.historial_dias, top=a.top,
                  sin_mascara=a.sin_mascara, ignorar=a.ignorar, ver_ip=a.ip))


if __name__ == "__main__":
    main()

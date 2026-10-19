"""Completa la geolocalizacion de eventos viejos que quedaron sin coordenadas.

Los eventos HTTP anteriores a la geolocalizacion y los FTP (que nunca la tuvieron) no
aparecen en el mapa. Este script les agrega pais, ciudad, ISP y coordenadas.

Uso (con el contenedor corriendo, dentro de la carpeta del proyecto):
    sudo docker compose exec honeypot python backfill_geo.py
    sudo docker compose exec honeypot python backfill_geo.py --dry-run   # solo cuenta

Respeta el limite de ip-api.com (~45 consultas por minuto en el plan gratuito): consulta
una IP unica cada ~1.6 s, asi que para ~100 IPs tarda unos 3 minutos. Si una IP falla,
se deja sin tocar y se puede reintentar corriendo el script otra vez.
"""
import json
import os
import sys
import time

from config import HTTP_LOG, FTP_LOG, es_ip_propia
from logger import _consultar_geolocation

PAUSA_SEG = 1.6
ARCHIVOS = [HTTP_LOG, FTP_LOG]


def necesita_geo(evento):
    return evento.get("lat") is None or evento.get("lon") is None


def leer(ruta):
    eventos = []
    if not os.path.exists(ruta):
        return eventos
    with open(ruta, "r") as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                eventos.append(json.loads(linea))
            except json.JSONDecodeError:
                eventos.append({"_cruda": linea})
    return eventos


def escribir(ruta, eventos):
    # Se reescribe sobre el mismo archivo (mismo inodo): el contenedor sigue escribiendo bien.
    with open(ruta, "w") as f:
        for e in eventos:
            if "_cruda" in e:
                f.write(e["_cruda"] + "\n")
            else:
                json.dump(e, f)
                f.write("\n")


def main():
    dry = "--dry-run" in sys.argv
    por_archivo = {ruta: leer(ruta) for ruta in ARCHIVOS}

    # IPs unicas que hay que consultar (sin repetir, sin IPs propias)
    pendientes = []
    vistas = set()
    for eventos in por_archivo.values():
        for e in eventos:
            ip = e.get("ip")
            if not ip or "_cruda" in e or not necesita_geo(e) or ip in vistas:
                continue
            if es_ip_propia(ip):
                continue
            vistas.add(ip)
            pendientes.append(ip)

    total_eventos = sum(1 for ev in por_archivo.values() for e in ev
                        if "_cruda" not in e and necesita_geo(e))
    print(f"Eventos sin coordenadas: {total_eventos}. IPs unicas a consultar: {len(pendientes)}.")
    if dry or not pendientes:
        return

    print(f"Tiempo estimado: ~{int(len(pendientes) * PAUSA_SEG)} segundos.")
    resultados = {}
    for i, ip in enumerate(pendientes, 1):
        geo = _consultar_geolocation(ip)
        if geo.get("country") != "Desconocido" and geo.get("lat") is not None:
            resultados[ip] = geo
        print(f"  [{i}/{len(pendientes)}] {'ok' if ip in resultados else 'sin dato'}")
        time.sleep(PAUSA_SEG)

    # Volver a leer justo antes de escribir: el contenedor pudo agregar eventos mientras tanto.
    actualizados = 0
    for ruta in ARCHIVOS:
        eventos = leer(ruta)
        for e in eventos:
            ip = e.get("ip")
            if "_cruda" in e or ip not in resultados or not necesita_geo(e):
                continue
            g = resultados[ip]
            e.update({"country": g["country"], "city": g["city"], "isp": g["isp"],
                      "lat": g["lat"], "lon": g["lon"]})
            actualizados += 1
        escribir(ruta, eventos)
    print(f"Listo: {actualizados} eventos actualizados, "
          f"{len(pendientes) - len(resultados)} IPs sin dato (reintentar mas tarde).")


if __name__ == "__main__":
    main()

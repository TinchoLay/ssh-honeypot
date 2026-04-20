import json
import os
import folium
from collections import Counter
from config import LOG_FILE

def generar_mapa():
    attempts = []
    if not os.path.exists(LOG_FILE):
        print("No hay intentos registrados todavía.")
        return

    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    attempts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not attempts:
        print("No hay intentos registrados todavía.")
        return

    mapa = folium.Map(
        location=[20, 0],
        zoom_start=2,
        tiles="https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png",
        attr="CartoDB"
    )

    coordenadas = {}
    for attempt in attempts:
        lat = attempt.get("lat")
        lon = attempt.get("lon")

        if lat is None or lon is None:
            continue

        key = (lat, lon)
        if key not in coordenadas:
            coordenadas[key] = {
                "count": 0,
                "country": attempt.get("country", "Desconocido"),
                "city": attempt.get("city", "Desconocido"),
                "ips": set()
            }

        coordenadas[key]["count"] += 1
        coordenadas[key]["ips"].add(attempt.get("ip", ""))

    for (lat, lon), data in coordenadas.items():
        count = data["count"]
        radio = min(5 + (count * 3), 40)

        tooltip = f"""
        🌍 {data['country']} — {data['city']}
        💥 Ataques: {count}
        🖥️ IPs: {len(data['ips'])}
        """

        folium.CircleMarker(
            location=[lat, lon],
            radius=radio,
            color="#FF4444",
            fill=True,
            fill_color="#FF0000",
            fill_opacity=0.6,
            tooltip=tooltip
        ).add_to(mapa)

    output_file = "mapa_ataques.html"
    mapa.save(output_file)
    print(f"\n✅ Mapa generado: {output_file}")
    print(f"   Abrilo en tu navegador para verlo.")
    print(f"   Total de puntos en el mapa: {len(coordenadas)}")

if __name__ == "__main__":
    generar_mapa()
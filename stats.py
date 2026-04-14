import json
import os
from collections import Counter
from config import LOG_FILE

def load_attempts():
    """Lee todos los intentos guardados en el archivo JSON."""
    attempts = []
    
    if not os.path.exists(LOG_FILE):
        return attempts
    
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    attempts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    
    return attempts

def show_stats():
    """Muestra el resumen de ataques en consola."""
    attempts = load_attempts()
    
    if not attempts:
        print("\n  No se registraron intentos todavía.")
        return
    
    # .get() con valor por defecto evita el KeyError si el campo no existe
    usernames = Counter(a.get("username", "desconocido") for a in attempts)
    passwords = Counter(a.get("password", "desconocido") for a in attempts)
    countries = Counter(a.get("country", "desconocido") for a in attempts)
    ips       = Counter(a.get("ip", "desconocido") for a in attempts)
    
    linea = "═" * 45
    
    print(f"\n{linea}")
    print(f"{'RESUMEN DE ATAQUES':^45}")
    print(f"{linea}")
    print(f"  Total de intentos registrados: {len(attempts)}")
    print(f"  IPs únicas detectadas:         {len(ips)}")
    
    def mostrar_top(titulo, counter, n=5):
        print(f"\n  {titulo}:")
        for i, (valor, cantidad) in enumerate(counter.most_common(n), start=1):
            print(f"    {i}. {valor:<25} ({cantidad} veces)")
    
    mostrar_top("Top usuarios probados", usernames)
    mostrar_top("Top contraseñas usadas", passwords)
    mostrar_top("Top países atacantes", countries)
    mostrar_top("Top IPs atacantes", ips)
    
    print(f"\n{linea}\n")

if __name__ == "__main__":
    show_stats()
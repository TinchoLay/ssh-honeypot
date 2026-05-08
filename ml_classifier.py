import json
import os
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import pickle

MODEL_FILE = "logs/modelo_ml.pkl"
ML_LOG = "logs/ml_classifications.json"

# Credenciales comunes usadas por bots
USUARIOS_COMUNES = {"root", "admin", "user", "test", "ubuntu", "pi", 
                    "oracle", "postgres", "guest", "ftpuser", "www"}
PASSWORDS_COMUNES = {"123456", "password", "admin", "root", "12345", 
                     "1234", "test", "pass", "qwerty", "abc123", "letmein"}

# ─── DATOS DE ENTRENAMIENTO ────────────────────────────────────────────────────
# Como no tenemos datos reales todavía, creamos ejemplos sintéticos
# que representan cada tipo de atacante.
# Cada fila es: [velocidad, usuarios_distintos, passwords_distintas, 
#                uso_diccionario, interactuó_shell, ejecutó_comandos, variación]

DATOS_ENTRENAMIENTO = [
    # Bot de fuerza bruta — muy rápido, muchas combinaciones, diccionario
    [45, 3, 40, 1, 0, 0, 0.2],
    [60, 2, 55, 1, 0, 0, 0.1],
    [30, 5, 25, 1, 0, 0, 0.3],
    [80, 1, 70, 1, 0, 0, 0.1],
    [50, 4, 45, 1, 0, 0, 0.2],
    [35, 3, 30, 1, 0, 0, 0.15],
    [70, 2, 60, 1, 0, 0, 0.1],
    [25, 6, 20, 1, 0, 0, 0.4],

    # Scanner — muy rápido pero pocas credenciales, solo verifica si está abierto
    [20, 1, 1, 0, 0, 0, 0.05],
    [15, 1, 2, 0, 0, 0, 0.1],
    [25, 2, 1, 0, 0, 0, 0.05],
    [18, 1, 1, 1, 0, 0, 0.05],
    [22, 1, 2, 0, 0, 0, 0.08],
    [12, 2, 1, 0, 0, 0, 0.03],

    # Script kiddie — velocidad media, usa herramientas conocidas, poco creativo
    [10, 5, 10, 1, 1, 0, 1.5],
    [8,  4, 8,  1, 1, 0, 2.0],
    [12, 6, 12, 1, 1, 1, 1.2],
    [7,  3, 7,  1, 1, 0, 1.8],
    [15, 7, 15, 1, 1, 0, 1.0],
    [9,  5, 9,  1, 1, 1, 1.6],

    # Atacante dirigido — lento, pocos intentos, personalizado, explora la shell
    [2, 3, 2, 0, 1, 1, 8.0],
    [1, 2, 1, 0, 1, 1, 12.0],
    [3, 4, 3, 0, 1, 1, 6.0],
    [1, 2, 2, 0, 1, 1, 15.0],
    [2, 3, 1, 0, 1, 1, 10.0],
    [1, 1, 1, 0, 1, 1, 20.0],
]

ETIQUETAS = (
    ["bot_fuerza_bruta"] * 8 +
    ["scanner"] * 6 +
    ["script_kiddie"] * 6 +
    ["atacante_dirigido"] * 6
)

# ─── MODELO ───────────────────────────────────────────────────────────────────

# Registro de comportamiento por IP para extraer features en tiempo real
_comportamiento = defaultdict(lambda: {
    "intentos": [],
    "usuarios": set(),
    "passwords": set(),
    "uso_diccionario": 0,
    "interactuó_shell": False,
    "comandos_ejecutados": 0
})

def entrenar_modelo():
    """
    Entrena el modelo de clasificación con los datos sintéticos.
    
    Usamos RandomForest — un algoritmo que crea muchos árboles de decisión
    y combina sus resultados. Es robusto, funciona bien con pocos datos
    y es fácil de interpretar.
    """
    X = np.array(DATOS_ENTRENAMIENTO)
    y = np.array(ETIQUETAS)
    
    modelo = RandomForestClassifier(
        n_estimators=100,    # 100 árboles de decisión
        random_state=42,     # Semilla fija para reproducibilidad
        max_depth=5          # Profundidad máxima de cada árbol
    )
    modelo.fit(X, y)
    
    # Guardar el modelo entrenado en disco
    # Así no necesitamos re-entrenarlo cada vez que arranca el honeypot
    os.makedirs("logs", exist_ok=True)
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(modelo, f)
    
    print(f"  ✅ Modelo ML entrenado con {len(X)} ejemplos")
    return modelo

def cargar_modelo():
    """Carga el modelo desde disco o lo entrena si no existe."""
    if os.path.exists(MODEL_FILE):
        with open(MODEL_FILE, "rb") as f:
            return pickle.load(f)
    return entrenar_modelo()

# Cargar el modelo al importar el módulo
_modelo = cargar_modelo()

def extraer_features(ip):
    """
    Convierte el comportamiento observado de una IP en números
    que el modelo puede procesar.
    
    Esto se llama 'feature engineering' — transformar datos crudos
    en características útiles para el modelo.
    """
    comp = _comportamiento[ip]
    ahora = datetime.now()
    
    # Calcular velocidad — intentos en el último minuto
    ventana = ahora - timedelta(seconds=60)
    recientes = [t for t in comp["intentos"] if t > ventana]
    velocidad = len(recientes)
    
    # Calcular variación en el tiempo entre intentos
    # Alta variación = humano, baja variación = bot
    variacion = 0.0
    if len(comp["intentos"]) >= 3:
        ultimos = comp["intentos"][-5:]
        intervalos = [(ultimos[i] - ultimos[i-1]).total_seconds() 
                     for i in range(1, len(ultimos))]
        if intervalos:
            variacion = max(intervalos) - min(intervalos)
    
    return [
        velocidad,
        len(comp["usuarios"]),
        len(comp["passwords"]),
        1 if comp["uso_diccionario"] > 0 else 0,
        1 if comp["interactuó_shell"] else 0,
        min(comp["comandos_ejecutados"], 10),  # Cap en 10
        variacion
    ]

def registrar_intento_ml(ip, username, password):
    """Registra un intento de login para análisis posterior."""
    comp = _comportamiento[ip]
    comp["intentos"].append(datetime.now())
    comp["usuarios"].add(username.lower())
    comp["passwords"].add(password.lower())
    
    if username.lower() in USUARIOS_COMUNES or password.lower() in PASSWORDS_COMUNES:
        comp["uso_diccionario"] += 1

def registrar_shell_ml(ip, comando=None):
    """Registra interacción con la fake shell."""
    comp = _comportamiento[ip]
    comp["interactuó_shell"] = True
    if comando:
        comp["comandos_ejecutados"] += 1

def clasificar_atacante(ip):
    """
    Clasifica un atacante usando el modelo entrenado.
    Solo clasifica si hay suficientes datos (mínimo 3 intentos).
    """
    # IPs locales no se clasifican
    if ip.startswith("127.") or ip.startswith("192.168."):
        return None
    
    comp = _comportamiento[ip]
    if len(comp["intentos"]) < 3:
        return None
    
    features = extraer_features(ip)
    X = np.array([features])
    
    # Predecir la categoría
    categoria = _modelo.predict(X)[0]
    
    # Obtener la probabilidad de cada categoría
    # predict_proba devuelve la confianza del modelo para cada clase
    probabilidades = _modelo.predict_proba(X)[0]
    confianza = max(probabilidades) * 100
    
    resultado = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "categoria": categoria,
        "confianza": round(confianza, 1),
        "features": {
            "velocidad_intentos_min": features[0],
            "usuarios_distintos": features[1],
            "passwords_distintas": features[2],
            "uso_diccionario": bool(features[3]),
            "interactuó_shell": bool(features[4]),
            "comandos_ejecutados": features[5],
            "variacion_temporal": round(features[6], 2)
        }
    }
    
    # Guardar en log
    os.makedirs("logs", exist_ok=True)
    with open(ML_LOG, "a") as f:
        json.dump(resultado, f)
        f.write("\n")
    
    mostrar_clasificacion(resultado)
    return resultado

def mostrar_clasificacion(r):
    """Muestra la clasificación en consola con emojis según el tipo."""
    emojis = {
        "bot_fuerza_bruta": "🤖",
        "scanner":          "🔭",
        "script_kiddie":    "👾",
        "atacante_dirigido":"🎯"
    }
    
    descripciones = {
        "bot_fuerza_bruta": "Script automatizado de fuerza bruta",
        "scanner":          "Scanner buscando servicios abiertos",
        "script_kiddie":    "Usuario de herramientas conocidas",
        "atacante_dirigido":"Atacante humano con objetivo específico"
    }
    
    emoji = emojis.get(r["categoria"], "❓")
    desc = descripciones.get(r["categoria"], r["categoria"])
    
    print(f"\n  {'▓'*45}")
    print(f"  {emoji} ML Clasificación — {r['ip']}")
    print(f"  Tipo:       {desc}")
    print(f"  Confianza:  {r['confianza']}%")
    f = r["features"]
    print(f"  Velocidad:  {f['velocidad_intentos_min']} intentos/min")
    print(f"  Usuarios:   {f['usuarios_distintos']} distintos")
    print(f"  Passwords:  {f['passwords_distintas']} distintas")
    if f["interactuó_shell"]:
        print(f"  Shell:      Sí — {f['comandos_ejecutados']} comandos")
    print(f"  {'▓'*45}\n")

def reentrenar_con_logs():
    """
    Re-entrena el modelo usando los logs reales acumulados.
    Llamá esta función después de tener muchos ataques reales.
    Una vez que el honeypot esté expuesto a internet, los datos reales
    van a mejorar mucho la precisión del modelo.
    """
    if not os.path.exists(ML_LOG):
        print("No hay clasificaciones previas para re-entrenar.")
        return
    
    datos_reales = []
    etiquetas_reales = []
    
    with open(ML_LOG, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                f_data = r.get("features", {})
                datos_reales.append([
                    f_data.get("velocidad_intentos_min", 0),
                    f_data.get("usuarios_distintos", 0),
                    f_data.get("passwords_distintas", 0),
                    1 if f_data.get("uso_diccionario") else 0,
                    1 if f_data.get("interactuó_shell") else 0,
                    f_data.get("comandos_ejecutados", 0),
                    f_data.get("variacion_temporal", 0)
                ])
                etiquetas_reales.append(r["categoria"])
            except Exception:
                pass
    
    if len(datos_reales) < 10:
        print(f"Pocos datos reales ({len(datos_reales)}). Necesitás al menos 10 para re-entrenar.")
        return
    
    # Combinar datos sintéticos con datos reales
    X = np.array(DATOS_ENTRENAMIENTO + datos_reales)
    y = np.array(ETIQUETAS + etiquetas_reales)
    
    global _modelo
    _modelo = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=5)
    _modelo.fit(X, y)
    
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(_modelo, f)
    
    print(f"  ✅ Modelo re-entrenado con {len(datos_reales)} ejemplos reales + {len(DATOS_ENTRENAMIENTO)} sintéticos")

if __name__ == "__main__":
    # Si se corre directamente, re-entrena el modelo
    reentrenar_con_logs()